<?php
namespace SadranSecurity\Scanners;
use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

/**
 * File integrity scanner with baseline management, differences and admin alert.
 */
class FileIntegrityScanner {
    private static $instance = null;
    const CRON_HOOK = 'sadran_daily_file_scan';
    private $baseline_file;

    public static function instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->baseline_file = WP_CONTENT_DIR . '/uploads/.sadran_baseline.json';
    }

    public function maybe_schedule() {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), 'daily', self::CRON_HOOK);
        }
        add_action(self::CRON_HOOK, [$this, 'run_scan']);
    }

    /**
     * Build baseline (safe): only core/plugin/theme PHP files under wp-content and wp-includes
     */
    public function build_baseline() {
        $paths = [ABSPATH . 'wp-includes', WP_CONTENT_DIR . '/plugins', WP_CONTENT_DIR . '/themes'];
        $baseline = [];
        foreach ($paths as $p) {
            if (!is_dir($p)) continue;
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($p));
            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $fn = $f->getFilename();
                if (!preg_match('/\.(php|inc)$/i', $fn)) continue;
                $rel = str_replace(ABSPATH, '', $f->getPathname());
                $baseline[$rel] = md5_file($f->getPathname());
            }
        }
        @file_put_contents($this->baseline_file, wp_json_encode($baseline));
        return $baseline;
    }

    public function run_scan() {
        LogsDB::instance()->log('file_scan', 'File integrity scan started');
        // if baseline missing, build it and return
        if (!file_exists($this->baseline_file)) {
            $this->build_baseline();
            return;
        }

        $baseline = json_decode(@file_get_contents($this->baseline_file), true) ?: [];
        $current = [];

        // scan same directories
        $paths = [ABSPATH . 'wp-includes', WP_CONTENT_DIR . '/plugins', WP_CONTENT_DIR . '/themes'];
        foreach ($paths as $p) {
            if (!is_dir($p)) continue;
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($p));
            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $fn = $f->getFilename();
                if (!preg_match('/\.(php|inc)$/i', $fn)) continue;
                $rel = str_replace(ABSPATH, '', $f->getPathname());
                $current[$rel] = md5_file($f->getPathname());
            }
        }

        $changed = ['modified' => [], 'added' => [], 'removed' => []];
        // detect modifications and additions
        foreach ($current as $p => $h) {
            if (!isset($baseline[$p])) {
                $changed['added'][] = $p;
            } elseif ($baseline[$p] !== $h) {
                $changed['modified'][] = $p;
            }
        }
        // detect removals
        foreach ($baseline as $p => $h) {
            if (!isset($current[$p])) $changed['removed'][] = $p;
        }

        if (!empty($changed['added']) || !empty($changed['modified']) || !empty($changed['removed'])) {
            $this->report($changed);
            // update baseline automatically but log that baseline was updated
            @file_put_contents($this->baseline_file, wp_json_encode($current));
        }
        if (empty($changed['added']) && empty($changed['modified']) && empty($changed['removed'])) {
            LogsDB::instance()->log('file_scan', 'No changes detected', 1);
        }

    }

    private function report($changed) {
        LogsDB::instance()->log('file_scan', 'File changes detected', 3, $changed);

        $admin = get_option('admin_email');
        $subject = 'Sadran Security - File integrity changes detected';
        $body = "Detected file changes:\n\nAdded:\n" . implode("\n", $changed['added']) .
                 "\n\nModified:\n" . implode("\n", $changed['modified']) .
                 "\n\nRemoved:\n" . implode("\n", $changed['removed']);
        error_log('[SadranScanner] ' . substr($body, 0, 1000));
        @wp_mail($admin, $subject, $body);
        $inc = (array) get_option('sadran_incidents', []);
        $inc[] = ['time' => time(), 'type' => 'file_integrity', 'detail' => $changed];
        update_option('sadran_incidents', $inc);
    }
}
