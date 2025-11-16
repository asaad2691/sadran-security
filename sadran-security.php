<?php
/**
 * Plugin Name: Sadran Security
 * Plugin URI: https://github.com/sadran-security/sadran-security
 * Description: Next-generation WordPress security framework with hardening, malware scanning, intrusion detection, and server-guided remediation.
 * Version: 0.1.0
 * Author: Sadran Security Project
 * License: GPL-2.0-or-later
 * Text Domain: sadran-security
 */

if (!defined('ABSPATH')) {
    exit;
}

// Autoloader
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

// Bootstrap
add_action('plugins_loaded', function () {
    if (class_exists('SadranSecurity\\Core')) {
        SadranSecurity\Core::init();
    }
});
