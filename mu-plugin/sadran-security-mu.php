<?php
/**
 * Sadran Security MU Loader
 *
 * This file should be placed in wp-content/mu-plugins/ to ensure the plugin is always loaded.
 */

if ( defined( 'WP_CONTENT_DIR' ) ) {
    $plugin = WP_CONTENT_DIR . '/plugins/sadran-security/sadran-security.php';
    if ( file_exists( $plugin ) ) {
        require_once $plugin;
    }
}
