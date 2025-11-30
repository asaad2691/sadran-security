<?php
namespace SadranSecurity\Hardening;

use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

/**
 * Login hardening: attempts counter, blocklist, honeypot injection,
 * brute-force detection and login behavior logging.
 */
class LoginHardener {

    private static $instance = null;
    private $block_opt = 'sadran_blocked_ips';
    private $fail_transient_prefix = 'sadran_fail_';
    private $honeypot_field = 'sadran_hp';

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('login_form', [$this, 'output_honeypot']);
        add_action('wp_login_failed', [$this, 'on_fail']);
        add_action('wp_authenticate', [$this, 'block_on_auth'], 1);
        add_action('wp_login', [$this, 'on_success'], 10, 2);
    }

    /**
     * Hidden honeypot field injected into login form
     */
    public function output_honeypot() {
        echo '<input type="text" name="' . esc_attr($this->honeypot_field) . '" value="" style="display:none" autocomplete="off" />';
    }

    /**
     * On login failure: record attempt and detect brute force
     */
    public function on_fail($username) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $key = $this->fail_transient_prefix . md5($ip);
        $fails = (int) get_transient($key);
        $fails++;

        // Log failed attempt
        LogsDB::instance()->log('login_fail', 'Failed login attempt', 1, [
            'ip'   => $ip,
            'user' => $username,
            'fails' => $fails,
        ]);

        set_transient($key, $fails, 15 * MINUTE_IN_SECONDS);

        // If brute force detected
        if ($fails >= 6) {
            $blocked = (array) get_option($this->block_opt, []);
            if (!in_array($ip, $blocked)) {

                $blocked[] = $ip;
                update_option($this->block_opt, $blocked);

                LogsDB::instance()->log('bruteforce', 'IP blocked due to repeated failed logins', 3, [
                    'ip' => $ip
                ]);

                error_log('[SadranLogin] Blocked ' . $ip);
            }
        }
    }

    /**
     * Block authentication for blocked IP or honeypot triggers
     */
    public function block_on_auth() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $blocked = (array) get_option($this->block_opt, []);

        // If IP was blocked
        if ($ip && in_array($ip, $blocked)) {
            LogsDB::instance()->log('bruteforce', 'Blocked login attempt from blocked IP', 3, [
                'ip' => $ip
            ]);
            wp_die(__('Access temporarily blocked by Sadran Security', 'sadran-security'));
        }

        // Honeypot triggered
        if (!empty($_REQUEST[$this->honeypot_field])) {

            LogsDB::instance()->log('honeypot', 'Honeypot triggered (bot detected)', 3, [
                'ip' => $ip
            ]);

            $this->block_ip($ip);
            wp_die(__('Access temporarily blocked', 'sadran-security'));
        }
    }

    /**
     * Block IP manually
     */
    public function block_ip($ip) {
        if (!$ip) return;

        $blocked = (array) get_option($this->block_opt, []);
        if (!in_array($ip, $blocked)) {
            $blocked[] = $ip;
            update_option($this->block_opt, $blocked);
        }
    }

    /**
     * On successful login: reset counters + log event
     */
    public function on_success($user_login, $user) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$ip) return;

        delete_transient($this->fail_transient_prefix . md5($ip));

        LogsDB::instance()->log('login_success', 'Successful login', 1, [
            'user' => $user_login,
            'ip'   => $ip
        ]);
    }

    /**
     * Login protection indicator for UI badge
     */
    public function is_rate_limit_active() {
        return true;
    }
}
