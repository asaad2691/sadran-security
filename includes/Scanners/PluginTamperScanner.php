<?php
namespace SadranSecurity\Scanners;

use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

/**
 * PluginTamperScanner
 *
 * Detects suspicious / unsafe plugins based on known keywords
 * - file managers
 * - nulled indicators
 * - etc.
 *
 * Logs detailed structured metadata into LogsDB.
 */
class PluginTamperScanner {

    private static $instance = null;

    private $suspicious_keywords = [
        'file-manager',
        'wp-file-manager',
        'unlimitedwp',
        'nulled',
        'codecanyon',
        'wpmanager',
        'shell',
        'backdoor'
    ];

    public static function instance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action('admin_init', [$this, 'scan_plugins_admin']);
    }

    /**
     * Scan installed plugins for suspicious clues.
     */
    public function scan_plugins_admin() {
        if (!is_admin() || !current_user_can('manage_options')) return;

        // WordPress plugin list
        $all = get_plugins();
        $found = [];

        foreach ($all as $path => $meta) {
            $slug = dirname($path);
            if ($slug === '.' || $slug === '') $slug = sanitize_title($meta['Name']);

            foreach ($this->suspicious_keywords as $keyword) {
                if (
                    stripos($slug, $keyword) !== false ||
                    stripos($meta['Name'], $keyword) !== false ||
                    stripos($meta['Description'], $keyword) !== false
                ) {
                    $found[] = [
                        'slug'   => $slug,
                        'name'   => $meta['Name'],
                        'path'   => $path,
                        'keyword'=> $keyword,
                    ];
                    break;
                }
            }
        }

        /* If suspicious plugins exist */
        if (!empty($found)) {

            LogsDB::instance()->log(
                'plugin_tamper',
                'Suspicious plugin activity detected',
                2,
                [
                    'count' => count($found),
                    'plugins' => $found
                ]
            );

            $names = array_map(function($x){
                return $x['name'] . ' (' . $x['slug'] . ')';
            }, $found);

            $msg = "Sadran Security: Suspicious plugins detected — " . implode(', ', $names);

            add_action('admin_notices', function() use ($msg) {
                echo '<div class="notice notice-error"><p>' . esc_html($msg) . '</p></div>';
            });

            // Store incident
            $inc = (array) get_option('sadran_incidents', []);
            $inc[] = [
                'time' => time(),
                'type' => 'plugin_tamper',
                'detail' => $found
            ];
            update_option('sadran_incidents', $inc);

            return;
        }

        /* If everything is clean */
        LogsDB::instance()->log(
            'plugin_tamper',
            'No suspicious plugin activity detected',
            1,
            [
                'checked' => count($all),
                'keywords' => $this->suspicious_keywords
            ]
        );
    }
}
