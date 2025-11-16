<?php
namespace SadranSecurity\Hardening;


if (!defined('ABSPATH')) {
exit;
}

/**
* Login hardening: rate-limiting, blocklist, enforce no-common-usernames.
* Conservative: logs and sets transient-based blocks; doesn't change passwords.
*/

class LoginHardener {
    private static $instance = null;
    private $block_option = 'sadran_blocked_ips';


    public static function instance() {
    if (null === self::$instance) {
    self::$instance = new self();
    }
    return self::$instance;
    }


    private function __construct() {
    add_action('wp_login_failed', array($this, 'on_login_failed'));
    add_action('wp_authenticate', array($this, 'block_on_auth'), 1);
    add_action('wp_login', array($this, 'clear_on_success'), 10, 2);
    }

    public function on_login_failed($username) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $key = 'sadran_fail_' . md5($ip);
    $fails = (int) get_transient($key);
    $fails++;
    set_transient($key, $fails, 15 * MINUTE_IN_SECONDS);


    if ($fails >= 6) {
    $blocked = (array) get_option($this->block_option, array());
    if (!in_array($ip, $blocked)) {
    $blocked[] = $ip;
    update_option($this->block_option, $blocked);
    error_log('[SadranSecurity] Blocking IP ' . $ip . ' after ' . $fails . ' failed attempts');
    }
    }
    }


    public function block_on_auth() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $blocked = (array) get_option($this->block_option, array());
    if ($ip && in_array($ip, $blocked)) {
    wp_die('Access temporarily blocked.');
    }
    }


    public function clear_on_success($user_login, $user) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!$ip) return;
    $key = 'sadran_fail_' . md5($ip);
    delete_transient($key);
    }




/**
* Utility to check for common usernames on install; warns admin.
*/

public function check_common_username() {
$common = array('admin','administrator','root','user');
foreach ($common as $c) {
if (username_exists($c)) {
add_action('admin_notices', function() use ($c){
echo '<div class="notice notice-warning"><p>Sadran Security: found common username "' . esc_html($c) . '" - consider renaming or removing it.</p></div>';
});
}
}
}
}