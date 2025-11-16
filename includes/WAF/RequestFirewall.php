<?php
namespace SadranSecurity\WAF;

if (!defined('ABSPATH')) exit;

/**
 * Lightweight request firewall with signatures for eval/base64, SQLi, XSS, file requests.
 * Conservative: blocks and logs.
 */
class RequestFirewall {
    private static $instance = null;
    private $signatures = [];

    public static function instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->init_signatures();
        add_action('parse_request', [$this, 'early_check'], 0);
    }

    private function init_signatures() {
        $base = [
            // RCE / eval / obfuscation
            '/(eval|base64_decode|gzinflate|gzuncompress|shell_exec|exec|passthru|assert|preg_replace\\(.*\\/e/)/i',
            // suspicious file requests
            '/wp-content\\/uploads\\/.*\\.(php|phtml|php5)$/i',
            // .env or config leaks
            '/(^|\\/)(\\.env|wp-config\\.php|config\\.php)/i',
            // SQLi-like patterns
            "/(union(.*?)select|select\\s+\\*\\s+from|information_schema|sleep\\(|benchmark\\()/i",
            // XSS-ish attempts in query strings or POST
            '/(<script\\b|onerror=|onload=|<svg|javascript:)/i'
        ];

        $this->signatures = apply_filters('sadran_waf_signatures', $base);
    }

    public function early_check() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        $body = '';

        if ($method === 'POST') {
            if (!empty($_POST)) $body = json_encode($_POST);
            else $body = file_get_contents('php://input') ?: '';
        }

        foreach ($this->signatures as $sig) {
            if (preg_match($sig, $uri) || ($body && preg_match($sig, $body))) {
                $this->block_request($sig);
            }
        }
    }

    private function block_request($sig) {
        if (defined('WP_DEBUG') && WP_DEBUG) error_log('[SadranWAF] Blocked ' . ($_SERVER['REQUEST_URI'] ?? '') . ' sig:' . $sig);
        status_header(403);
        header('Content-Type: text/plain');
        echo 'Forbidden';
        exit;
    }
}
