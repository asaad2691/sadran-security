<?php
namespace SadranSecurity\Admin;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Minimal admin page to run scans and show incidents.
 */
class AdminPage {
    private static $instance = null;

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function register() {
        add_action( 'admin_menu', array( $this, 'add_menu' ) );
        add_action( 'admin_init', array( $this, 'handle_actions' ) );
    }

    public function add_menu() {
        add_menu_page(
            'Sadran Security',
            'Sadran Security',
            'manage_options',
            'sadran-security',
            array( $this, 'render_page' ),
            'dashicons-shield',
            3
        );
    }

    public function handle_actions() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        if ( isset( $_POST['sadran_run_scan'] ) && check_admin_referer( 'sadran_run_scan' ) ) {
            // call scanner directly (non-blocking)
            if ( class_exists( 'SadranSecurity\\Scanners\\FileIntegrityScanner' ) ) {
                SadranSecurity\Scanners\FileIntegrityScanner::instance()->run_scan();
                add_settings_error( 'sadran_messages', 'scan_ran', esc_html__( 'Scan completed. Check incident log below.', 'sadran-security' ), 'updated' );
            }
        }
    }

    public function render_page() {
        $inc = (array) get_option( 'sadran_incidents', array() );
        settings_errors( 'sadran_messages' );
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'Sadran Security', 'sadran-security' ); ?></h1>
            <form method="post">
                <?php wp_nonce_field( 'sadran_run_scan' ); ?>
                <p>
                    <button type="submit" name="sadran_run_scan" class="button button-primary"><?php esc_html_e( 'Run File Integrity Scan', 'sadran-security' ); ?></button>
                </p>
            </form>

            <h2><?php esc_html_e( 'Incidents', 'sadran-security' ); ?></h2>
            <?php if ( empty( $inc ) ) : ?>
                <p><?php esc_html_e( 'No incidents logged.', 'sadran-security' ); ?></p>
            <?php else : ?>
                <ul>
                    <?php foreach ( array_reverse( $inc ) as $item ) : ?>
                        <li>
                            <strong><?php echo esc_html( date( 'c', $item['time'] ) ); ?></strong> — <em><?php echo esc_html( $item['type'] ); ?></em>
                            <pre style="white-space:pre-wrap;"><?php echo esc_html( is_array( $item['detail'] ) ? implode( "\n", $item['detail'] ) : $item['detail'] ); ?></pre>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
        <?php
    }
}
