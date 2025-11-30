<?php
namespace SadranSecurity\Hardening;

use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

/**
 * Hardener controller — handles toggleable security measures.
 */
class Hardener {

    private static $instance = null;
    private $opt_prefix = 'sadran_hardening_';

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('init', [$this, 'apply_runtime_hardening'], 1);
    }

    public function is_enabled($key) {
        return (bool) get_option($this->opt_prefix . $key, false);
    }

    public function set_enabled($key, $val) {
        update_option($this->opt_prefix . $key, $val ? 1 : 0);
    }

    /**
     * Applies all hardening rules based on enabled settings.
     */
    public function apply_runtime_hardening() {

        LogsDB::instance()->log('hardening', 'Hardening runtime rules executed', 1);

        /**
         * DISABLE FILE EDITOR
         */
        if ($this->is_enabled('disable_file_edit')) {

            LogsDB::instance()->log('hardening', 'File editor disabled');

            add_filter('user_has_cap', function($allcaps){
                if (isset($allcaps['edit_plugins'])) $allcaps['edit_plugins'] = false;
                if (isset($allcaps['edit_themes']))  $allcaps['edit_themes']  = false;
                return $allcaps;
            }, 999);
        }

        /**
         * DISABLE XML-RPC
         */
        if ($this->is_enabled('disable_xmlrpc')) {

            LogsDB::instance()->log('hardening', 'XML-RPC disabled');

            add_filter('xmlrpc_enabled', '__return_false');

            add_filter('init', function() {
                if (php_sapi_name() !== 'cli' && stripos($_SERVER['REQUEST_URI'] ?? '', 'xmlrpc.php') !== false) {
                    status_header(403);
                    exit;
                }
            }, 0);
        }

        /**
         * RESTRICT REST API
         */
        if ($this->is_enabled('restrict_rest')) {

            LogsDB::instance()->log('hardening', 'REST API restricted to authenticated users');

            add_filter('rest_authentication_errors', function($result){
                if (!empty($result)) return $result;

                if (is_user_logged_in()) return $result;

                $allow = [
                    '/wp/v2/posts', // keep public read-only endpoints open
                ];
                $uri = $_SERVER['REQUEST_URI'] ?? '';

                foreach ($allow as $a) {
                    if (stripos($uri, $a) !== false) return $result;
                }

                return new \WP_Error(
                    'rest_restricted',
                    'The REST API is restricted.',
                    ['status' => 403]
                );
            }, 10);
        }

        /**
         * BLOCK BAD USER-AGENTS
         */
        if ($this->is_enabled('block_bad_ua')) {

            LogsDB::instance()->log('hardening', 'Bad user-agent blocking enabled');

            add_action('init', function() {
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                if (!$ua) return;

                $deny = ['zmEu', 'nikto', 'acunetix', 'sqlmap', 'fimap', 'masscan', 'netsparker'];
                foreach ($deny as $d) {
                    if (stripos($ua, $d) !== false) {
                        status_header(403);
                        exit;
                    }
                }
            }, 0);
        }

        /**
         * UPLOADS .HTACCESS PROTECTION
         */
        if ($this->is_enabled('uploads_htaccess')) {

            LogsDB::instance()->log('hardening', 'Uploads folder .htaccess protection enabled');

            $this->deploy_uploads_htaccess();
        }
    }

    /**
     * Writes .htaccess in uploads folder to block PHP execution
     */
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
