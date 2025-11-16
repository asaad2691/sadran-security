<?php
namespace SadranSecurity\Admin;

if (!defined('ABSPATH')) exit;

class AdminUI {

    private static $instance = null;

    public static function instance() {
        if (!self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('wp_ajax_sadran_run_scan', [$this, 'ajax_run_scan']);
    }

    public function menu() {
        add_menu_page(
            'Sadran Security',
            'Sadran Security',
            'manage_options',
            'sadran-security',
            [$this, 'render'],
            'dashicons-shield',
            3
        );
    }

    public function assets() {
        wp_enqueue_style('sadran-admin', SADRAN_PLUGIN_URL . 'assets/css/admin.css', [], '1.0');
        wp_enqueue_script('sadran-admin-js', SADRAN_PLUGIN_URL . 'assets/js/admin.js', ['jquery'], '1.0', true);

        wp_localize_script('sadran-admin-js', 'SADRAN_AJAX', [
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('sadran_nonce')
        ]);
    }

    public function render() {
        $tab = $_GET['tab'] ?? 'overview';
        include SADRAN_PLUGIN_DIR . "admin/tabs/header.php";

        switch ($tab) {
            case 'scanners':
                include SADRAN_PLUGIN_DIR . "admin/tabs/scanners.php";
                break;

            case 'hardening':
                include SADRAN_PLUGIN_DIR . "admin/tabs/hardening.php";
                break;

            case 'logs':
                include SADRAN_PLUGIN_DIR . "admin/tabs/logs.php";
                break;

            case 'settings':
                include SADRAN_PLUGIN_DIR . "admin/tabs/settings.php";
                break;

            default:
                include SADRAN_PLUGIN_DIR . "admin/tabs/overview.php";
                break;
        }

        echo "</div>";
    }

    public function ajax_run_scan() {
        check_ajax_referer('sadran_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        if (class_exists('SadranSecurity\\Scanners\\FileIntegrityScanner')) {
            \SadranSecurity\Scanners\FileIntegrityScanner::instance()->run_scan();
        }

        wp_send_json_success('Scan completed.');
    }
}
