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
        // start log
        LogsDB::instance()->log('file_scan', 'File integrity scan started', 1, []);

        // if baseline missing, build it and return
        if (!file_exists($this->baseline_file)) {
            $this->build_baseline();
            LogsDB::instance()->log('file_scan', 'Baseline missing - created baseline', 1, ['baseline_created' => true]);
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
                $changed['added'][$p] = ['hash' => $h];
            } elseif ($baseline[$p] !== $h) {
                $changed['modified'][$p] = [
                    'old_hash' => $baseline[$p],
                    'new_hash' => $h,
                ];
            }
        }
        // detect removals
        foreach ($baseline as $p => $h) {
            if (!isset($current[$p])) $changed['removed'][$p] = ['old_hash' => $h];
        }

        $has_changes = !empty($changed['added']) || !empty($changed['modified']) || !empty($changed['removed']);

        if ($has_changes) {
            $this->report($changed);

            // update baseline automatically but log that baseline was updated
            @file_put_contents($this->baseline_file, wp_json_encode($current));
            LogsDB::instance()->log('file_scan', 'Baseline updated after changes', 1, ['updated' => true]);
        } else {
            // no changes
            $stats = ['scanned' => count($current), 'added' => 0, 'modified' => 0, 'removed' => 0];
            LogsDB::instance()->log('file_scan', 'No changes detected', 1, $stats);
        }
    }

    private function report($changed) {
        // Prepare human message and meta
        $added = array_keys($changed['added']);
        $modified = array_keys($changed['modified']);
        $removed = array_keys($changed['removed']);

        $meta = [
            'time' => time(),
            'added' => $changed['added'],
            'modified' => $changed['modified'],
            'removed' => $changed['removed'],
            'counts' => [
                'added' => count($added),
                'modified' => count($modified),
                'removed' => count($removed),
            ]
        ];

        // Log to LogsDB with detailed meta
        LogsDB::instance()->log('file_scan', 'File changes detected', 3, $meta);

        // Email admin summary (kept short)
        $admin = get_option('admin_email');
        $subject = 'Sadran Security - File integrity changes detected';
        $body = "Detected file changes:\n\nAdded:\n" . implode("\n", $added) .
                 "\n\nModified:\n" . implode("\n", $modified) .
                 "\n\nRemoved:\n" . implode("\n", $removed);
        error_log('[SadranScanner] ' . substr($body, 0, 1000));
        @wp_mail($admin, $subject, $body);

        // store incident snapshot
        $inc = (array) get_option('sadran_incidents', []);
        $inc[] = ['time' => time(), 'type' => 'file_integrity', 'detail' => $meta];
        update_option('sadran_incidents', $inc);
    }
}
