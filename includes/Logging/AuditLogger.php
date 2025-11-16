<?php
namespace SadranSecurity\Logging;

if (!defined('ABSPATH')) exit;

/**
 * Simple audit logger stored in wp_options (small sites). Optionally swap to custom table later.
 */
class AuditLogger {
    private static $option = 'sadran_audit_log';
    private static $max_items = 250;

    public static function log($type, $detail = '') {
        $items = (array) get_option(self::$option, []);
        $items[] = ['t' => time(), 'type' => $type, 'detail' => $detail];
        if (count($items) > self::$max_items) $items = array_slice($items, -self::$max_items);
        update_option(self::$option, $items);
    }

    public static function get($limit = 100) {
        $items = (array) get_option(self::$option, []);
        return array_reverse(array_slice($items, 0, $limit));
    }
}
