<?php
namespace SadranSecurity\Scanners;
use SadranSecurity\Logging\LogsDB;


if (!defined('ABSPATH')) {
exit;
}


/**
* Detects suspicious plugins (file managers, nulled indicators) and reports them.
* Non-destructive: can optionally deactivate a plugin but defaults to notify only.
*/

class PluginTamperScanner {
private static $instance = null;
private $suspicious_keywords = array('file-manager', 'wp-file-manager', 'unlimitedwp', 'nulled', 'codecanyon');


public static function instance() {
if (null === self::$instance) {
self::$instance = new self();
}
return self::$instance;
}


private function __construct() {
add_action('admin_init', array($this, 'scan_plugins_admin'));
}

public function scan_plugins_admin() {
    if (!is_admin() || !current_user_can('manage_options')) return;

    $all = get_plugins();
    $found = array();

    foreach ($all as $path => $meta) {
        $slug = dirname($path);
        foreach ($this->suspicious_keywords as $k) {
            if (
                stripos($slug, $k) !== false ||
                stripos($meta['Name'], $k) !== false ||
                stripos($meta['Description'], $k) !== false
            ) {
                $found[] = array(
                    'slug' => $slug,
                    'name' => $meta['Name']
                );
            }
        }
    }

    if (!empty($found)) {

        LogsDB::instance()->log(
            'plugin_tamper',
            'Suspicious plugins detected',
            2,
            $found
        );

        $message = "Sadran Security: suspicious plugins found: ";
        $names = array_map(function($i){
            return $i['name'] . ' (' . $i['slug'] . ')';
        }, $found);
        $message .= implode(', ', $names);

        add_action('admin_notices', function() use ($message){
            echo '<div class="notice notice-error"><p>' . esc_html($message) . '</p></div>';
        });

        // store incident
        $inc = (array) get_option('sadran_incidents', array());
        $inc[] = array(
            'time' => time(),
            'type' => 'suspicious_plugins',
            'detail' => $names
        );
        update_option('sadran_incidents', $inc);
    }

    else {

        LogsDB::instance()->log(
            'plugin_tamper',
            'No suspicious plugin activity detected',
            1
        );

    }
}
    
}