<?php
namespace SadranSecurity\Logging;

if (!defined('ABSPATH')) exit;

class LogsDB {

    private static $instance = null;
    private $table;

    public static function instance() {
        if (!self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'sadran_logs';
    }

    /**
     * Create logs table on plugin activation
     * Ensures BOTH meta + extra_json exist.
     */
    public function install_table() {
        global $wpdb;

        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$this->table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            time INT(11) NOT NULL,
            ip VARCHAR(45) NOT NULL,
            type VARCHAR(50) NOT NULL,
            message TEXT NOT NULL,
            severity TINYINT(2) DEFAULT 1,
            meta LONGTEXT NULL,
            extra_json LONGTEXT NULL,
            PRIMARY KEY (id),
            KEY time (time),
            KEY type (type),
            KEY severity (severity)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        update_option('sadran_logs_installed', 1);
    }

    /**
     * Insert log entry
     * Saves meta → meta AND extra_json for UI compatibility.
     */
    public function log($type, $message, $severity = 1, $meta = []) {
        global $wpdb;

        // Ensure meta is ALWAYS an array
        if (!is_array($meta)) $meta = [];

        $json = wp_json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $wpdb->insert($this->table, [
            'time'       => time(),
            'ip'         => sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'),
            'type'       => sanitize_text_field($type),
            'message'    => sanitize_text_field($message),
            'severity'   => absint($severity),
            'meta'       => $json,
            'extra_json' => $json,
        ]);
    }

    /**
     * Fetch logs with limit + offset
     */
    public function fetch($limit = 50, $offset = 0) {
        global $wpdb;

        $limit  = absint($limit);
        $offset = absint($offset);

        $results = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$this->table} ORDER BY id DESC LIMIT %d OFFSET %d", $limit, $offset)
        );

        return array_map([$this, 'format_row'], $results);
    }

    /**
     * Count all logs
     */
    public function count() {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->table}");
    }

    /**
     * Return most recent logs
     */
    public function get_recent($limit = 50) {
        global $wpdb;

        $limit = absint($limit);

        $results = $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$this->table} ORDER BY id DESC LIMIT %d", $limit)
        );

        return array_map([$this, 'format_row'], $results);
    }

    /**
     * Helper to decode meta / extra_json properly
     */
    public function format_row($row) {
        $row->meta_array = [];

        // Prefer meta
        if (!empty($row->meta)) {
            $decoded = json_decode($row->meta, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $row->meta_array = $decoded;
                return $row;
            }
        }

        // Fallback: extra_json
        if (!empty($row->extra_json)) {
            $decoded = json_decode($row->extra_json, true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $row->meta_array = $decoded;
            }
        }

        return $row;
    }

    /**
     * For external use — get table name safely
     */
    public function get_table() {
        return $this->table;
    }
}
