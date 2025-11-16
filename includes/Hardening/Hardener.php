<?php
namespace SadranSecurity\Hardening;

if (!defined('ABSPATH')) exit;

/**
 * Hardener controller: applies and toggles hardening measures.
 * Non destructive by default; writes .htaccess and enforces WP options.
 */
class Hardener {
    private static $instance = null;
    private $opt_prefix = 'sadran_hardening_';

    public static function instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        // apply simple hardening immediately if enabled
        add_action('init', [$this, 'apply_runtime_hardening'], 1);
    }

    public function is_enabled($key) {
        return (bool) get_option($this->opt_prefix . $key, false);
    }

    public function set_enabled($key, $val) {
        update_option($this->opt_prefix . $key, $val ? 1 : 0);
    }

    public function apply_runtime_hardening() {
        // Disable file editor if enabled
        if ($this->is_enabled('disable_file_edit')) {
            add_filter('user_has_cap', function($allcaps){
                if (isset($allcaps['edit_plugins'])) $allcaps['edit_plugins'] = false;
                if (isset($allcaps['edit_themes']))  $allcaps['edit_themes']  = false;
                return $allcaps;
            }, 999);
        }

        // Disable XML-RPC
        if ($this->is_enabled('disable_xmlrpc')) {
            add_filter('xmlrpc_enabled', '__return_false');
            // block access to xmlrpc.php
            add_filter('init', function() {
                if (php_sapi_name() !== 'cli' && stripos($_SERVER['REQUEST_URI'] ?? '', 'xmlrpc.php') !== false) {
                    status_header(403); exit;
                }
            }, 0);
        }

        // Restrict REST API: only authenticated (unless allowlist)
        if ($this->is_enabled('restrict_rest')) {
            add_filter('rest_authentication_errors', function($result){
                if (!empty($result)) return $result;
                // allow if user is logged in or route is allowlisted
                if (is_user_logged_in()) return $result;
                $allow = [
                    '/wp/v2/posts', // example - continue to open read-only endpoints if needed
                ];
                $uri = $_SERVER['REQUEST_URI'] ?? '';
                foreach ($allow as $a) {
                    if (stripos($uri, $a) !== false) return $result;
                }
                return new \WP_Error('rest_restricted', 'The REST API is restricted.', [ 'status' => 403 ]);
            }, 10);
        }

        // Auto-block bad user-agents
        if ($this->is_enabled('block_bad_ua')) {
            add_action('init', function(){
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                if (!$ua) return;
                $deny = [ 'zmEu', 'nikto', 'acunetix', 'sqlmap', 'fimap', 'masscan', 'netsparker' ];
                foreach ($deny as $d) {
                    if (stripos($ua, $d) !== false) {
                        status_header(403); exit;
                    }
                }
            }, 0);
        }

        // Create safe .htaccess in uploads (idempotent)
        if ($this->is_enabled('uploads_htaccess')) {
            $this->deploy_uploads_htaccess();
        }
    }

    public function deploy_uploads_htaccess() {
        $uploads = wp_upload_dir();
        $dir = $uploads['basedir'] ?? false;
        if (!$dir || !is_dir($dir) || !is_writable($dir)) return false;

        $ht = <<<HT
# Sadran Security - prevent PHP execution
<IfModule mod_php7.c>
<FilesMatch "\.(php|php5|phtml)$">
    Require all denied
</FilesMatch>
</IfModule>

<IfModule !mod_php7.c>
<FilesMatch "\.(php|php5|phtml)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
</IfModule>
HT;
        $file = $dir . DIRECTORY_SEPARATOR . '.htaccess';
        if (!file_exists($file) || file_get_contents($file) !== $ht) {
            @file_put_contents($file, $ht);
        }
        return true;
    }
}
