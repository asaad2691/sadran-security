<?php
namespace SadranSecurity\Hardening;

use SadranSecurity as CoreNS;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Prevents PHP execution in uploads and ensures a safety .htaccess is present (Apache).
 * Non-destructive: it writes .htaccess only if safe to do so.
 */
class UploadsProtector {
    private static $instance = null;

    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // noop
    }

    /**
     * Deploy protections (idempotent).
     */
    public function deploy_protection() {
        $uploads = wp_upload_dir();
        $basedir = isset( $uploads['basedir'] ) ? $uploads['basedir'] : false;
        if ( ! $basedir || ! is_dir( $basedir ) || ! is_writable( $basedir ) ) {
            return;
        }

        $ht = $this->apache_htaccess_contents();
        $file = $basedir . DIRECTORY_SEPARATOR . '.htaccess';

        // Only write if file does not exist or contents differ.
        if ( ! file_exists( $file ) || md5_file( $file ) !== md5( $ht ) ) {
            @file_put_contents( $file, $ht );
        }

        // Create a PHP file block for nginx users (optional notice file)
        $deny_file = $basedir . DIRECTORY_SEPARATOR . 'sadran-deny.php';
        if ( ! file_exists( $deny_file ) ) {
            @file_put_contents( $deny_file, "<?php\n// Sadran Security: uploads - remove PHP execution.\nexit;\n" );
        }
    }

    private function apache_htaccess_contents() {
        return <<<HT
# Sadran Security - block PHP execution in uploads
<IfModule mod_php7.c>
<FilesMatch "\.(php|php5|phtml)$">
    Require all denied
</FilesMatch>
</IfModule>

<IfModule !mod_php7.c>
<FilesMatch "\.(php|php5|phtml)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
</IfModule>

# deny direct access to known sensitive filenames
<FilesMatch "(^sadran-deny\.php|^.*\.phps$)">
    Require all denied
</FilesMatch>
HT;
    }
}
