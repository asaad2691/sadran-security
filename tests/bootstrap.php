<?php
// Basic PHPUnit bootstrap for WordPress plugin testing.
// Placeholder: integrate WP test suite later.
require dirname(__DIR__) . '/vendor/autoload.php';


define('SADRAN_TEST_ROOT', dirname(__DIR__));


// Minimal constants
if (!defined('ABSPATH')) {
define('ABSPATH', SADRAN_TEST_ROOT . '/wp/'); // adjust to local WP test install
}


// Mock functions as needed during early development
if (!function_exists('wp_upload_dir')) {
function wp_upload_dir() {
return [ 'basedir' => SADRAN_TEST_ROOT . '/uploads' ];
}
}