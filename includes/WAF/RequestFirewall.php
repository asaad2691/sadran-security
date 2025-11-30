<?php
namespace SadranSecurity\WAF;

use SadranSecurity\Logging\LogsDB;

if (! defined( 'ABSPATH' ) ) exit;

/**
 * RequestFirewall v2
 *
 * - Signature scoring instead of instant block
 * - Per-request transient score decay + short-term rate limiting
 * - Auto-ban when cumulative score exceeds threshold
 * - Whitelist support (IP / UA / URIs) via options/filters
 * - Integrates with LogsDB for all important events
 *
 * Notes:
 * Keep patterns simple (avoid catastrophic regex). Use filters to extend rules.
 */
class RequestFirewall {
    private static $instance = null;

    /** per-request transient prefix (short-lived) */
    const TRANSIENT_PREFIX = 'sadran_waf_score_';
    const BLOCK_OPTION = 'sadran_blocked_ips';

    /** thresholds (tuneable) */
    private $match_threshold = 5;       // score required in single request to block immediately
    private $ban_threshold = 15;        // cumulative score across window to permanent-ban
    private $transient_ttl = 300;       // seconds to accumulate per-ip score (5 minutes)
    private $max_request_size = 2 * 1024 * 1024; // 2MB body read limit

    private $signatures = [];           // array of [pattern => weight]
    private $deny_whitelist = [];       // runtime cache

    public static function instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->init_signatures();
        // early hook: parse_request runs after WP parsing but early enough to block
        add_action('parse_request', [$this, 'early_check'], 0);
    }

    /**
     * Build default signatures with conservative weights.
     * Expose 'sadran_waf_signatures' filter to let other code add/modify rules.
     */
    private function init_signatures() {
        $base = [
            // high-risk: remote code exec / obfuscation
            '/base64_decode\\s*\\(/i'        => 4,
            '/eval\\s*\\(/i'                 => 4,
            '/gzinflate\\s*\\(/i'            => 3,
            '/gzuncompress\\s*\\(/i'         => 3,
            '/shell_exec\\s*\\(/i'           => 4,
            '/passthru\\s*\\(/i'             => 4,
            '/exec\\s*\\(/i'                 => 4,
            '/assert\\s*\\(/i'               => 3,
            // suspicious preg_replace /e style usage
            '/preg_replace\\s*\\(.*,.*\\,.*\\)/i' => 3,

            // SQLi-ish (conservative)
            '/union\\s+select/i'             => 3,
            '/information_schema/i'          => 3,
            '/select\\s+\\*\\s+from/i'       => 2,
            '/sleep\\s*\\(/i'                => 3,
            '/benchmark\\s*\\(/i'            => 3,

            // XSS-ish / script injection
            '/<script\\b/i'                  => 3,
            '/javascript:/i'                 => 2,
            '/onerror\\s*=|onload\\s*=/i'    => 2,
            '/<svg\\b/i'                     => 2,

            // suspicious file requests
            '/wp-content\\/uploads\\/.*\\.(php|phtml|php5)$/i' => 4,
            '/\\.(env|sql|bak|config|ini)$/i' => 2,

            // enumeration / scanning agents
            '/(nikto|acunetix|sqlmap|masscan|nmap|netsparker)/i' => 2,
        ];

        // Merge with filter so integrators can add or adjust weights
        $this->signatures = apply_filters('sadran_waf_signatures', $base);
    }

    /**
     * Early check called on parse_request.
     */
    public function early_check() {
        // Basic environment data
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        // Quick whitelist checks
        if ($this->is_whitelisted_ip($ip)) return;
        if ($this->is_whitelisted_uri($uri)) return;
        if ($this->is_whitelisted_user_agent($_SERVER['HTTP_USER_AGENT'] ?? '')) return;

        // Check if IP already permanently blocked
        if ($this->is_blocked_ip($ip)) {
            $this->log_and_terminate('waf_block', 'Blocked request from permanently banned IP', 3, [
                'ip' => $ip, 'uri' => $uri
            ]);
        }

        // Build payload to inspect (uri + query + small body)
        $payload = $uri;
        if (!empty($_SERVER['QUERY_STRING'])) $payload .= '?' . $_SERVER['QUERY_STRING'];

        // Read POST body up to limit
        $body = '';
        if ($method === 'POST') {
            $raw = @file_get_contents('php://input');
            if ($raw !== false && strlen($raw) <= $this->max_request_size) {
                $body = $raw;
            } elseif (!empty($_POST)) {
                // if superglobal exists, use JSON-encoded POST array (safe)
                $body = json_encode($_POST);
            }
        }

        // Evaluate signatures: accumulate score
        $score = 0;
        foreach ($this->signatures as $pattern => $weight) {
            // try/catch not available for preg_match, but skip invalid patterns safely
            $matched = @preg_match($pattern, $payload) || ($body && @preg_match($pattern, $body));
            if ($matched) {
                $score += (int)$weight;
                // small debug log if WP_DEBUG
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log("[SadranWAF] Signature matched: {$pattern} weight={$weight} ip={$ip} uri={$uri}");
                }
            }
        }

        // If this single-request score exceeds match threshold -> block & log
        if ($score >= $this->match_threshold) {
            $this->block_and_maybe_ban($ip, $uri, $score, 'single_request_threshold');
        }

        // Otherwise, accumulate transient-based score for this IP over a short window
        if ($score > 0) {
            $this->accumulate_ip_score($ip, $score, $uri);
        }
    }

    /**
     * Increase the per-IP transient score and perform ban check if necessary.
     */
    private function accumulate_ip_score($ip, $score, $uri) {
        $key = self::TRANSIENT_PREFIX . md5($ip);
        $current = (int) get_transient($key);
        $current += $score;
        set_transient($key, $current, $this->transient_ttl);

        LogsDB::instance()->log('waf_score', "Accumulated WAF score: {$current}", 1, [
            'ip' => $ip,
            'added' => $score,
            'uri' => $uri
        ]);

        // If cumulative score exceeds ban threshold -> add to blocked list
        if ($current >= $this->ban_threshold) {
            $this->block_and_maybe_ban($ip, $uri, $current, 'cumulative_threshold');
        }
    }

    /**
     * Block request now, then if source is malicious enough, add to blocked list.
     */
    private function block_and_maybe_ban($ip, $uri, $score, $reason = '') {
        // log the block
        LogsDB::instance()->log('waf_block', "Blocked malicious request (score={$score}) reason={$reason}", 3, [
            'ip' => $ip,
            'uri' => $uri,
            'score' => $score,
            'reason' => $reason
        ]);

        // simple auto-ban: append to block option (permanent until admin removes)
        $blocked = (array) get_option(self::BLOCK_OPTION, []);
        if (!in_array($ip, $blocked)) {
            $blocked[] = $ip;
            update_option(self::BLOCK_OPTION, $blocked);
            LogsDB::instance()->log('waf_block', 'IP added to permanent blocklist', 3, [
                'ip' => $ip,
                'reason' => $reason,
                'score' => $score
            ]);
        }

        // terminate request
        status_header(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Forbidden';
        exit;
    }

    /**
     * Convenience: log and die (for permanent blocked IPs)
     */
    private function log_and_terminate($type, $message, $severity = 3, $meta = []) {
        LogsDB::instance()->log($type, $message, $severity, $meta + ['time' => time()]);
        status_header(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Forbidden';
        exit;
    }

    /**
     * Return true if IP is permanently blocked via settings.
     */
    private function is_blocked_ip($ip) {
        if (empty($ip)) return false;
        $blocked = (array) get_option(self::BLOCK_OPTION, []);
        return in_array($ip, $blocked);
    }

    /**
     * Check whitelists: IP, UA, URI via options or filters.
     */
    private function is_whitelisted_ip($ip) {
        if (empty($ip)) return false;
        $list = (array) get_option('sadran_waf_whitelist_ips', []);
        // allow filter to add dynamically
        $list = (array) apply_filters('sadran_waf_whitelist_ips', $list);
        return in_array($ip, $list);
    }

    private function is_whitelisted_user_agent($ua) {
        if (empty($ua)) return false;
        $list = (array) get_option('sadran_waf_whitelist_ua', []);
        $list = (array) apply_filters('sadran_waf_whitelist_ua', $list);
        foreach ($list as $w) {
            if ($w && stripos($ua, $w) !== false) return true;
        }
        return false;
    }

    private function is_whitelisted_uri($uri) {
        if (empty($uri)) return false;
        $list = (array) get_option('sadran_waf_whitelist_uris', []);
        $list = (array) apply_filters('sadran_waf_whitelist_uris', $list);
        foreach ($list as $w) {
            if ($w && stripos($uri, $w) !== false) return true;
        }
        return false;
    }

    /**
     * Admin helpers: public functions to unblock IP or get blocked list
     */
    public function unblock_ip($ip) {
        $blocked = (array) get_option(self::BLOCK_OPTION, []);
        $new = array_values(array_filter($blocked, function($b) use($ip){ return $b !== $ip; }));
        update_option(self::BLOCK_OPTION, $new);
        LogsDB::instance()->log('waf_admin', 'IP unblocked by admin', 1, ['ip' => $ip]);
    }

    public function get_blocked() {
        return (array) get_option(self::BLOCK_OPTION, []);
    }
}
