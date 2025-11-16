<?php
/**
 * MU Loader for Sadran Security
 */

if (!defined('WP_CONTENT_DIR')) {
    return;
}

$plugin_path = WP_CONTENT_DIR . '/plugins/sadran-security/sadran-security.php';

if (file_exists($plugin_path)) {
    include_once $plugin_path;
}
