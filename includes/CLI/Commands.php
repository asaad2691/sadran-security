<?php
namespace SadranSecurity\CLI;


if (!defined('ABSPATH')) {
return;
}



/**
* WP-CLI commands for Sadran Security.
* Usage:
* wp sadran scan --type=file-integrity
*/

class Commands {
public static function register() {
if (defined('WP_CLI') && WP_CLI) {
\WP_CLI::add_command('sadran scan', array(__CLASS__, 'cmd_scan'));
}
}


public static function cmd_scan($args, $assoc) {
$type = $assoc['type'] ?? 'file-integrity';
switch ($type) {
case 'file-integrity':
if (class_exists('SadranSecurity\\Scanners\\FileIntegrityScanner')) {
SadranSecurity\Scanners\FileIntegrityScanner::instance()->run_scan();
\WP_CLI::success('File integrity scan completed.');
} else {
\WP_CLI::error('FileIntegrityScanner not available.');
}
break;
case 'plugin-tamper':
if (class_exists('SadranSecurity\\Scanners\\PluginTamperScanner')) {
SadranSecurity\Scanners\PluginTamperScanner::instance()->scan_plugins_admin();
\WP_CLI::success('Plugin tamper scan triggered (admin-only checks).');
} else {
\WP_CLI::error('PluginTamperScanner not available.');
}
break;
default:
\WP_CLI::warning('Unknown scan type. Supported: file-integrity, plugin-tamper');
break;
}
}
}


// Register on plugins_loaded
add_action('plugins_loaded', function(){
if (class_exists('SadranSecurity\\CLI\\Commands')) {
SadranSecurity\\CLI\\Commands::register();
}
});