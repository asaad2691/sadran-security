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

    /**
     * Initialize plugin
     */
    public static function init( $plugin_file ) {
        if ( self::$instance ) {
            return self::$instance;
        }

        self::$plugin_file = $plugin_file;
        self::$instance = new self();

        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        $this->define_constants();
        $this->includes();
        $this->register_hooks();
    }

    /**
     * Define constants used across the plugin.
     */
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

    /**
     * Load all plugin modules
     */
    private function includes() {

        // HARDENING
        require_once SADRAN_PLUGIN_DIR . 'includes/Hardening/UploadsProtector.php';
        require_once SADRAN_PLUGIN_DIR . 'includes/Hardening/LoginHardener.php';

        // WAF
        require_once SADRAN_PLUGIN_DIR . 'includes/WAF/RequestFirewall.php';

        // SCANNERS
        require_once SADRAN_PLUGIN_DIR . 'includes/Scanners/FileIntegrityScanner.php';
        require_once SADRAN_PLUGIN_DIR . 'includes/Scanners/PluginTamperScanner.php';

        // ADMIN UI
        require_once SADRAN_PLUGIN_DIR . 'admin/AdminUI.php';

        // CLI Commands (optional)
        require_once SADRAN_PLUGIN_DIR . 'includes/CLI/Commands.php';
    }

    /**
     * Register WP hooks
     */
    private function register_hooks() {
        add_action( 'init', [ $this, 'boot' ], 5 );
    }

    /**
     * Boot plugin components (runs after WP core init)
     */
    public function boot() {

        // PROTECTION
        Hardening\UploadsProtector::instance()->deploy_protection();
        Hardening\LoginHardener::instance()->check_common_username();

        // WAF
        WAF\RequestFirewall::instance();

        // SCANNERS
        Scanners\FileIntegrityScanner::instance()->maybe_schedule();
        Scanners\PluginTamperScanner::instance(); // auto-runs on admin_init

        // ADMIN UI — THIS MAKES THE SIDEBAR MENU SHOW UP
        \SadranSecurity\Admin\AdminUI::instance();

        // WP CLI
        if ( defined('WP_CLI') && WP_CLI ) {
            \SadranSecurity\CLI\Commands::register();
        }
    }
}
