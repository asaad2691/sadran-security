<?php
namespace SadranSecurity\Hardening;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * HardeningManager
 *
 * Central controller that applies and manages all hardening features.
 * Reads options prefixed with sadran_hardening_ and applies runtime protections.
 */
class HardeningManager {
    private static $instance = null;
    private $opt_prefix = 'sadran_hardening_';

    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // Register actions that should be present regardless of options
        add_action('init', [$this, 'apply_runtime_protections'], 1);
    }

    /**
     * Main entry — apply all selected protections
     */
    public function apply_runtime_protections() {
        // Apply each feature if enabled in options
        if ($this->is_enabled('disable_file_edit')) {
            $this->disable_file_editor();
        }

        if ($this->is_enabled('disable_xmlrpc')) {
            $this->disable_xmlrpc();
        }

        if ($this->is_enabled('restrict_rest')) {
            $this->restrict_rest();
        }

        if ($this->is_enabled('block_bad_ua')) {
            $this->block_user_agents();
        }

        if ($this->is_enabled('uploads_htaccess')) {
            UploadsProtector::instance()->deploy_protection();
        }

        // Hook login hardener initialization (ensures class loaded)
        LoginHardener::instance(); // constructor sets necessary hooks

        // Register admin notices for guidance (non-invasive)
        add_action('admin_notices', [$this, 'admin_guidance']);
    }

    /**
     * Return whether option is enabled (bool)
     */
    public function is_enabled(string $key) : bool {
        return (bool) get_option($this->opt_prefix . $key, false);
    }

    /**
     * Disable WP file editor by defining constant
     */
    private function disable_file_editor() {
        if (! defined('DISALLOW_FILE_EDIT')) {
            if (!defined('SADRAN_FILE_EDIT_DISABLED')) {
                // define temporary constant for current request
                define('DISALLOW_FILE_EDIT', true);
                define('SADRAN_FILE_EDIT_DISABLED', 1);
            }
        }
    }

    /**
     * Disable XML-RPC access
     */
    private function disable_xmlrpc() {
        add_filter('xmlrpc_enabled', '__return_false');
        // block direct access to xmlrpc.php early
        add_action('init', function () {
            if (php_sapi_name() !== 'cli' && isset($_SERVER['REQUEST_URI']) && stripos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
                status_header(403);
                exit;
            }
        }, 0);
    }

    /**
     * Restrict REST API for unauthenticated users (allow read-only endpoints optionally)
     */
    private function restrict_rest() {
        add_filter('rest_authentication_errors', function ($result) {
            if (! empty($result)) {
                return $result;
            }
            if (is_user_logged_in()) {
                return $result;
            }

            // Allow read-only public endpoints optionally (safe list)
            $allowlist = apply_filters('sadran_rest_allowlist', [
                '/wp/v2/posts',
                '/wp/v2/pages',
            ]);
            $uri = $_SERVER['REQUEST_URI'] ?? '';
            foreach ($allowlist as $a) {
                if (stripos($uri, $a) !== false) {
                    return $result;
                }
            }

            return new \WP_Error('rest_restricted', 'The REST API is restricted by Sadran Security.', ['status' => 403]);
        }, 10);
    }

    /**
     * Block some common bad user agents early to reduce noise and brute scanners.
     */
    private function block_user_agents() {
        add_action('init', function () {
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
            if (! $ua) return;
            $deny_list = apply_filters('sadran_bad_user_agents', [
                'acunetix', 'nikto', 'sqlmap', 'fimap', 'masscan', 'nmap', 'netsparker', 'curl', 'wget', 'python-requests'
            ]);

            $ua_low = strtolower($ua);
            foreach ($deny_list as $bad) {
                if (stripos($ua_low, $bad) !== false) {
                    if (defined('WP_DEBUG') && WP_DEBUG) error_log('[Sadran] Blocked UA: ' . $ua);
                    status_header(403);
                    header('Content-Type: text/plain; charset=utf-8');
                    echo 'Forbidden';
                    exit;
                }
            }
        }, 0);
    }

    /**
     * Admin guidance notice: when there are recommended host-level actions, show non-invasive instructions.
     */
    public function admin_guidance() {
        // Only show to administrators
        if (! current_user_can('manage_options')) return;

        // Example: warn if uploads htaccess trying to be applied but file not writable
        if ($this->is_enabled('uploads_htaccess')) {
            $uploads = wp_get_upload_dir();
            $basedir = isset($uploads['basedir']) ? $uploads['basedir'] : false;
            if ($basedir && is_dir($basedir) && !is_writable($basedir)) {
                echo '<div class="notice notice-warning"><p><strong>Sadran Security:</strong> Uploads protection could not write to the uploads folder. Please ensure uploads folder is writable or apply the .htaccess rules manually. <em>Path: ' . esc_html($basedir) . '</em></p></div>';
            }
        }

        // Example: if REST restricted, instruct about possible API whitelisting
        if ($this->is_enabled('restrict_rest')) {
            echo '<div class="notice notice-info"><p><strong>Sadran Security:</strong> REST API restriction is enabled. If you rely on third-party services, add them to the allowlist via the <code>sadran_rest_allowlist</code> filter in theme/plugin.</p></div>';
        }
    }

    /**
     * Utility: apply all protections on demand (programmatic one-click)
     */
    public function apply_all_now() {
        // deploy uploads htaccess if enabled
        if ($this->is_enabled('uploads_htaccess')) {
            UploadsProtector::instance()->deploy_protection();
        }
        // enforce DISALLOW_FILE_EDIT by setting option (persistent)
        if ($this->is_enabled('disable_file_edit')) {
            // persistent flag already saved by settings; this ensures runtime effect
            if (! defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }
        // other runtime protections are already applied by hooks
        return true;
    }
}
