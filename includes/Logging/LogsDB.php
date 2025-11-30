<?php
namespace SadranSecurity\Logging;

if (!defined('ABSPATH')) exit;

/**
 * LogsDB
 *
 * Responsible for creating, inserting, fetching Sadran logs.
 */
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
            meta LONGTEXT NULL,
            severity TINYINT(2) DEFAULT 1,
            PRIMARY KEY (id),
            INDEX (time),
            INDEX (type),
            INDEX (severity)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        update_option('sadran_logs_installed', 1);
    }

    /**
     * Insert a log entry
     */
    public function log($type, $message, $severity = 1, $meta = []) {
        global $wpdb;

        $wpdb->insert($this->table, [
            'time'     => time(),
            'ip'       => $_SERVER['REMOTE_ADDR'] ?? '',
            'type'     => sanitize_text_field($type),
            'message'  => sanitize_text_field($message),
            'meta'     => wp_json_encode($meta),
            'severity' => absint($severity),
        ]);
    }

    /**
     * Fetch logs (limit + offset)
     */
    public function fetch($limit = 50, $offset = 0) {
        global $wpdb;
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->table} ORDER BY id DESC LIMIT %d OFFSET %d",
                $limit,
                $offset
            )
        );
    }

    /**
     * Count total logs
     */
    public function count() {
        global $wpdb;
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->table}");
    }
    /**
     * Fetch recent logs (default 50).
     *
     * @param int $limit
     * @return array of stdClass rows
     */
    public function get_recent($limit = 50) {
        global $wpdb;

        $table = $this->table;

        $limit = intval($limit);
        if ($limit <= 0) $limit = 50;

        // Return newest first
        return $wpdb->get_results("
            SELECT id, type, time, message, extra_json, meta, created_at
            FROM {$table}
            ORDER BY id DESC
            LIMIT {$limit}
        ");
    }

}
