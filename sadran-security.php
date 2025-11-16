<?php
/**
 * Plugin Name: Sadran Security
 * Plugin URI:  https://github.com/asaad2691/sadran-security
 * Description: Next-generation WordPress security framework with hardening, scanning, integrity monitoring and guided remediation.
 * Version:     0.1.0
 * Author:      Sadran Security Project
 * License:     GPL-2.0-or-later
 * Text Domain: sadran-security
 */

if (! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Composer autoload if present.
 */
if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    // Basic fallback autoloader for includes/ classes (PSR-4 simple).
    spl_autoload_register( function ( $class ) {
        $prefix = 'SadranSecurity\\';
        if ( 0 !== strpos( $class, $prefix ) ) {
            return;
        }
        $relative = substr( $class, strlen( $prefix ) );
        $path = __DIR__ . '/includes/' . str_replace( '\\', '/', $relative ) . '.php';
        if ( file_exists( $path ) ) {
            require_once $path;
        }
    } );
}

/**
 * Bootstrap core.
 */
add_action( 'plugins_loaded', function () {
    if ( class_exists( 'SadranSecurity\\Core' ) ) {
        SadranSecurity\Core::init( __FILE__ );
    }
} );
