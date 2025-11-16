<?php
namespace SadranSecurity;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Core bootstrap for Sadran Security.
 */
class Core {
    /** @var string Absolute path to plugin main file */
    private static $plugin_file;

    /** @var Core|null */
    private static $instance = null;

    public static function init( $plugin_file ) {
        if ( self::$instance ) {
            return self::$instance;
        }
        self::$plugin_file = $plugin_file;
        self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->define_constants();
        $this->includes();
        $this->register_hooks();
    }

    private function define_constants() {
        if ( ! defined( 'SADRAN_PLUGIN_FILE' ) ) {
            define( 'SADRAN_PLUGIN_FILE', self::$plugin_file );
        }
        if ( ! defined( 'SADRAN_PLUGIN_DIR' ) ) {
            define( 'SADRAN_PLUGIN_DIR', trailingslashit( dirname( self::$plugin_file ) ) );
        }
        if ( ! defined( 'SADRAN_PLUGIN_URL' ) ) {
            define( 'SADRAN_PLUGIN_URL', trailingslashit( plugins_url( '', self::$plugin_file ) ) );
        }
    }

    private function includes() {
        // Core modules
        require_once SADRAN_PLUGIN_DIR . 'includes/Hardening/UploadsProtector.php';
        require_once SADRAN_PLUGIN_DIR . 'includes/Scanners/FileIntegrityScanner.php';
        require_once SADRAN_PLUGIN_DIR . 'includes/Admin/AdminPage.php';
    }

    private function register_hooks() {
        // Initialize modules on plugins_loaded (again) to allow WP to be ready
        add_action( 'init', array( $this, 'boot' ), 5 );
    }

    public function boot() {
        // Start protection and scanners
        Hardening\UploadsProtector::instance()->deploy_protection();
        Scanners\FileIntegrityScanner::instance()->maybe_schedule();
        Admin\AdminPage::instance()->register();
    }
}
