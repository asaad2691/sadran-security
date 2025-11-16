<?php
namespace SadranSecurity\WAF;


if (!defined('ABSPATH')) {
exit;
}

/**
* Lightweight request firewall. Inspects request URI, POST bodies and blocks common exploit patterns.
* This is a PHP-level early filter and cannot replace a real WAF, but it blocks many automated attacks.
*/

class RequestFirewall {
private static $instance = null;
private $signatures = null;

public static function instance() {
if (null === self::$instance) {
self::$instance = new self();
}
return self::$instance;
}


private function __construct() {
// minimal signature set; extensible via filter
$this->signatures = apply_filters('sadran_waf_signatures', array(
'/\b(eval|base64_decode|gzinflate|shell_exec|exec|passthru)\b/i',
'/(\.|\/)wp\-config\.php/i',
'/(\.|\/)\.env/i',
'/(\.|\/)wp\-content\/uploads\/.*\.(php|phtml|php5)$/i',
'/(\.|\/)wp\-admin\/admin\-ajax\.php\?.*action=/i'
));


add_action('plugins_loaded', array($this, 'early_check'), -100);
}

public function early_check() {
// Only run on front-end / admin-ajax / wp-login
$uri = $_SERVER['REQUEST_URI'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';


// Quick checks
foreach ($this->signatures as $sig) {
if (preg_match($sig, $uri) || ($method === 'POST' && $this->post_matches($sig))) {
$this->block_request($sig);
}
}
}


private function post_matches($sig) {
$body = '';
if (!empty($_POST)) {
$body = json_encode($_POST);
} else {
// php://input may contain raw payloads
$body = file_get_contents('php://input');
}
if (!$body) return false;
return preg_match($sig, $body);
}

private function block_request($matched) {
// Log and terminate
error_log('[SadranSecurity][WAF] Blocked request ' . ($_SERVER['REQUEST_URI'] ?? '') . ' signature: ' . $matched);
// Send a simple 403
http_response_code(403);
header('Content-Type: text/plain');
echo 'Forbidden.';
// stop further execution safely
exit;
}
}