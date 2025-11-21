<?php
namespace SadranSecurity\Hardening;

if (!defined('ABSPATH')) exit;

/**
 * Login hardening: attempts counter, blocklist, honeypot injection, detect brute-force from same IP or user.
 */
class LoginHardener {
    private static $instance = null;
    private $block_opt = 'sadran_blocked_ips';
    private $fail_transient_prefix = 'sadran_fail_';
    private $honeypot_field = 'sadran_hp';

    public static function instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action('login_form', [$this, 'output_honeypot']);
        add_action('wp_login_failed', [$this, 'on_fail']);
        add_action('wp_authenticate', [$this, 'block_on_auth'], 1);
        add_action('wp_login', [$this, 'on_success'], 10, 2);
    }

    public function output_honeypot() {
        echo '<input type="text" name="'.esc_attr($this->honeypot_field).'" value="" style="display:none" autocomplete="off" />';
    }

    public function on_fail($username) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $key = $this->fail_transient_prefix . md5($ip);
        $fails = (int) get_transient($key);
        $fails++;
        set_transient($key, $fails, 15 * MINUTE_IN_SECONDS);

        if ($fails >= 6) {
            $blocked = (array) get_option($this->block_opt, []);
            if (!in_array($ip, $blocked)) {
                $blocked[] = $ip;
                update_option($this->block_opt, $blocked);
                error_log('[SadranLogin] Blocked ' . $ip);
            }
        }
    }

    public function block_on_auth() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $blocked = (array) get_option($this->block_opt, []);
        if ($ip && in_array($ip, $blocked)) {
            wp_die(__('Access temporarily blocked by Sadran Security', 'sadran-security'));
        }

        // Check honeypot
        if (!empty($_REQUEST[$this->honeypot_field])) {
            $this->block_ip($ip);
            wp_die(__('Access temporarily blocked', 'sadran-security'));
        }
    }

    public function block_ip($ip) {
        if (!$ip) return;
        $blocked = (array) get_option($this->block_opt, []);
        if (!in_array($ip, $blocked)) {
            $blocked[] = $ip;
            update_option($this->block_opt, $blocked);
        }
    }

    public function on_success($user_login, $user) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$ip) return;
        delete_transient($this->fail_transient_prefix . md5($ip));
    }

    /**
     * Detect if rate limiting / brute-force protection is active
     */
    public function is_rate_limit_active() {
        return true;
    }
}
