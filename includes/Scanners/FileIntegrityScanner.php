<?php
namespace SadranSecurity\Scanners;

use SadranSecurity as CoreNS;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Lightweight file integrity scanner.
 * Stores a local baseline in wp-content/uploads/.sadran_baseline.json by default.
 * Non-destructive: reports changes and optionally emails the admin.
 */
class FileIntegrityScanner {
    private static $instance = null;
    const CRON_HOOK = 'sadran_daily_file_scan';

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private $baseline_file;

    private function __construct() {
        $this->baseline_file = WP_CONTENT_DIR . '/uploads/.sadran_baseline.json';
    }

    public function maybe_schedule() {
        if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
            wp_schedule_event( time(), 'daily', self::CRON_HOOK );
        }
        add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );
    }

    /**
     * Run the scan now (can be called manually).
     */
    public function run_scan() {
        $site_root = ABSPATH;
        $skip = array( 'wp-content/uploads', 'wp-content/cache', 'node_modules', '.git' );

        $current = array();
        $it = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $site_root ) );
        foreach ( $it as $f ) {
            if ( ! $f->isFile() ) {
                continue;
            }
            $path = $f->getPathname();
            $rel  = str_replace( $site_root, '', $path );
            // Skip large directories
            $skip_this = false;
            foreach ( $skip as $s ) {
                if ( 0 === strpos( $rel, $s ) ) {
                    $skip_this = true;
                    break;
                }
            }
            if ( $skip_this ) {
                continue;
            }
            $current[ $rel ] = md5_file( $path );
        }

        // Load previous baseline
        $prev = array();
        if ( file_exists( $this->baseline_file ) ) {
            $raw = @file_get_contents( $this->baseline_file );
            $prev = json_decode( $raw, true ) ?: array();
        }

        // If baseline missing, create it
        if ( empty( $prev ) ) {
            @file_put_contents( $this->baseline_file, wp_json_encode( $current ) );
            return;
        }

        $changed = array();
        foreach ( $current as $p => $h ) {
            if ( ! isset( $prev[ $p ] ) || $prev[ $p ] !== $h ) {
                $changed[] = $p;
            }
        }

        if ( ! empty( $changed ) ) {
            $this->report_changed_files( $changed );
            // Update baseline for now — in production consider requiring manual review
            @file_put_contents( $this->baseline_file, wp_json_encode( $current ) );
        }
    }

    private function report_changed_files( $changed ) {
        $admin = get_option( 'admin_email' );
        $subject = 'Sadran Security: Modified files detected';
        $body = "Sadran Security detected modified or new files on your site:\n\n" . implode( "\n", $changed );
        // log for server logs (helpful during incident)
        error_log( '[SadranSecurity] Modified files detected: ' . implode( ', ', $changed ) );
        // send an email notification (non-blocking)
        @wp_mail( $admin, $subject, $body );
        // store an incident entry
        $inc = (array) get_option( 'sadran_incidents', array() );
        $inc[] = array( 'time' => time(), 'type' => 'modified_files', 'detail' => $changed );
        update_option( 'sadran_incidents', $inc );
    }
}
