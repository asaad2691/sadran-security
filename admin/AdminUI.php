<?php
namespace SadranSecurity\Admin;

if (!defined('ABSPATH')) exit;

class AdminUI {

    private static $instance = null;

    public static function instance() {
        if (!self::$instance) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {

        /** ADMIN MENU + ASSETS */
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        

        
        /** DARK MODE */
        add_action('admin_head', [$this, 'apply_dark_mode']);
        /** AJAX HANDLERS */
        add_action('wp_ajax_sadran_run_scan', [$this, 'ajax_run_scan']);
        add_action('wp_ajax_sadran_run_malware', [$this, 'ajax_run_malware']);
        add_action('wp_ajax_sadran_apply_hardening', [$this, 'ajax_apply_hardening']);

        add_action('wp_ajax_sadran_dashboard_data', [$this, 'ajax_dashboard_data']);
        add_action('wp_ajax_sadran_clear_logs', [$this, 'ajax_clear_logs']);
        add_action('wp_ajax_sadran_filter_logs', [$this, 'ajax_filter_logs']);
        add_action('wp_ajax_sadran_dashboard_poll', [$this, 'ajax_dashboard_poll']);

    }

    public function ajax_dashboard_poll() {
        check_ajax_referer('sadran_nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        $last_id = isset($_POST['last_id']) ? intval($_POST['last_id']) : 0;
        global $wpdb;
        $table = $wpdb->prefix . 'sadran_logs';

        if ($last_id <= 0) {
            // fallback: return the last 5 entries
            $rows = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 5" );
            wp_send_json_success(['logs' => $rows]);
        }

        // return rows with id greater than last_id (new logs)
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$table} WHERE id > %d ORDER BY id ASC LIMIT 200",
            $last_id
        ) );

        // Also return the new total count
        $new_total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

        wp_send_json_success([
            'logs' => $rows,
            'total' => $new_total,
        ]);
    }


    public function ajax_filter_logs() {
        check_ajax_referer('sadran_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Not allowed');

        $db = \SadranSecurity\Logging\LogsDB::instance();

        $type     = sanitize_text_field($_POST['type'] ?? '');
        $severity = sanitize_text_field($_POST['severity'] ?? '');
        $range    = intval($_POST['range'] ?? 30);
        $search   = sanitize_text_field($_POST['search'] ?? '');
        $start    = sanitize_text_field($_POST['start'] ?? '');
        $end      = sanitize_text_field($_POST['end'] ?? '');

        global $wpdb;
        $table = $db->get_table();

        $where = " WHERE 1=1 ";

        if ($type !== '')       $where .= $wpdb->prepare(" AND type = %s", $type);
        if ($severity !== '')   $where .= $wpdb->prepare(" AND severity = %d", intval($severity));
        if ($search !== '')     $where .= $wpdb->prepare(" AND (message LIKE %s OR meta LIKE %s)", "%$search%", "%$search%");

        if ($range > 0) {
            $min_time = time() - ($range * 86400);
            $where   .= $wpdb->prepare(" AND time >= %d", $min_time);
        }

        if ($range == -1 && $start && $end) {
            $start_ts = strtotime($start);
            $end_ts   = strtotime($end . ' 23:59:59');
            $where   .= $wpdb->prepare(" AND time BETWEEN %d AND %d", $start_ts, $end_ts);
        }

        $rows = $wpdb->get_results("SELECT * FROM {$table} {$where} ORDER BY id DESC LIMIT 200");

        wp_send_json_success($rows);
    }
    
    public function ajax_dashboard_data() {
        check_ajax_referer('sadran_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        $db = \SadranSecurity\Logging\LogsDB::instance();
        global $wpdb;
        $table = $wpdb->prefix . 'sadran_logs';

        /** PAGE + PAGINATION **/
        $page     = isset($_POST['page']) ? intval($_POST['page']) : 1;
        if ($page < 1) $page = 1;

        $per_page = 10;
        $offset   = ($page - 1) * $per_page;

        // Fetch paginated logs
        $logs = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            )
        );

        $total       = $db->count();
        $total_pages = ceil($total / $per_page);

        /**
         * -----------------------------
         * CHART / AGGREGATE PROCESSING
         * -----------------------------
         */
        $now = time();
        $days = 30;
        $threats_by_day = array_fill(0, $days, 0);
        $labels = [];

        for ($i = $days - 1; $i >= 0; $i--) {
            $t = strtotime("-{$i} days");
            $labels[] = date('Y-m-d', $t);
        }

        $severity = [
            'critical' => 0,
            'high'     => 0,
            'medium'   => 0,
            'info'     => 0
        ];

        $waf_counts = [];

        // Use last 200 logs for charts (not paginated)
        $chart_logs = $db->get_recent(200);

        foreach ($chart_logs as $row) {

            // time normalize
            $ts = null;
            if (!empty($row->time) && is_numeric($row->time)) {
                $ts = intval($row->time);
            } elseif (!empty($row->created_at)) {
                $ts = strtotime($row->created_at);
            }

            if ($ts) {
                $diffDays = floor(($now - $ts) / 86400);
                if ($diffDays >= 0 && $diffDays < $days) {
                    $idx = $days - 1 - $diffDays;
                    if (isset($threats_by_day[$idx])) {
                        $threats_by_day[$idx]++;
                    }
                }
            }

            // severity
            $sev = isset($row->severity) ? intval($row->severity) : 1;

            if ($sev >= 3)      $severity['critical']++;
            elseif ($sev == 2)  $severity['high']++;
            elseif ($sev == 1)  $severity['medium']++;
            else                $severity['info']++;

            // waf signatures
            $meta = null;

            if (!empty($row->meta)) {
                $meta = json_decode($row->meta, true);
            } elseif (!empty($row->extra_json)) {
                $meta = json_decode($row->extra_json, true);
            }

            if ($meta && isset($meta['signature'])) {
                $sig = substr($meta['signature'], 0, 60);
                if (!isset($waf_counts[$sig])) $waf_counts[$sig] = 0;
                $waf_counts[$sig]++;
            } elseif ($row->type === 'waf_block') {
                $key = $row->message ?? 'waf_block';
                if (!isset($waf_counts[$key])) $waf_counts[$key] = 0;
                $waf_counts[$key]++;
            }
        }

        // Sort WAF counts, take top 10
        arsort($waf_counts);
        $waf_labels = array_slice(array_keys($waf_counts), 0, 10);
        $waf_values = array_slice(array_values($waf_counts), 0, 10);

        /**
         * RESPONSE
         */
        wp_send_json_success([
            'logs'          => $logs,
            'total'         => $total,
            'total_pages'   => $total_pages,
            'page'          => $page,
            'threats_by_day'=> ['labels' => $labels, 'values' => $threats_by_day],
            'severity'      => $severity,
            'waf_labels'    => $waf_labels,
            'waf_values'    => $waf_values,
        ]);
    }



    public function ajax_clear_logs() {
        check_ajax_referer('sadran_nonce');

        global $wpdb;
        $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}sadran_logs");

        wp_send_json_success('Logs cleared.');
    }

    /* ============================================================
       MALWARE SCANNER AJAX
    ============================================================ */
    public function ajax_run_malware() {

        check_ajax_referer('sadran_nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        if (class_exists('SadranSecurity\\Scanners\\MalwareScanner')) {

            $scan = \SadranSecurity\Scanners\MalwareScanner::instance()->run_scan();
            wp_send_json_success($scan);
        }

        wp_send_json_error('Malware scanner missing');
    }


    /* ============================================================
       APPLY HARDENING (Button)
    ============================================================ */
    public function ajax_apply_hardening() {
        check_ajax_referer('sadran_nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        if (!class_exists('\SadranSecurity\Hardening\HardeningManager')) {
            wp_send_json_error('HardeningManager missing');
        }

        $ok = \SadranSecurity\Hardening\HardeningManager::instance()->apply_all_now();
        $ok ? wp_send_json_success('Applied') : wp_send_json_error('Failed');
    }


    /* ============================================================
       ADMIN MENU / RENDER
    ============================================================ */
    public function menu() {
        add_menu_page(
            'Sadran Security',
            'Sadran Security',
            'manage_options',
            'sadran-security',
            [$this, 'render'],
            'dashicons-shield',
            3
        );
    }

    public function render() {

        $tab = $_GET['tab'] ?? 'overview';

        include SADRAN_PLUGIN_DIR . "admin/tabs/header.php";

        switch ($tab) {
            case 'dashboard':
                include SADRAN_PLUGIN_DIR . "admin/tabs/dashboard.php";
                break;

            case 'scanners':
                include SADRAN_PLUGIN_DIR . "admin/tabs/scanners.php";
                break;

            case 'hardening':
                include SADRAN_PLUGIN_DIR . "admin/tabs/hardening.php";
                break;

            case 'logs':
                include SADRAN_PLUGIN_DIR . "admin/tabs/logs.php";
                break;

            case 'settings':
                include SADRAN_PLUGIN_DIR . "admin/tabs/settings.php";
                break;

            default:
                include SADRAN_PLUGIN_DIR . "admin/tabs/overview.php";
                break;
        }

        echo "</div>";
    }

    /* ============================================================
       FILE INTEGRITY SCAN AJAX
    ============================================================ */
    public function ajax_run_scan() {
        check_ajax_referer('sadran_nonce');

        if (! current_user_can('manage_options')) {
            wp_send_json_error('Not allowed');
        }

        if (class_exists('SadranSecurity\\Scanners\\FileIntegrityScanner')) {
            \SadranSecurity\Scanners\FileIntegrityScanner::instance()->run_scan();
            wp_send_json_success('Integrity scan completed.');
        }

        wp_send_json_error('FileIntegrityScanner missing');
    }


    /* ============================================================
       ASSETS
    ============================================================ */
    public function assets() {

        wp_enqueue_style(
            'sadran-admin',
            SADRAN_PLUGIN_URL . 'assets/css/admin.css',
            [],
            '1.0'
        );

        wp_enqueue_script(
            'sadran-admin-js',
            SADRAN_PLUGIN_URL . 'assets/js/admin.js',
            ['jquery'],
            '1.0',
            true
        );

        wp_localize_script('sadran-admin-js', 'SADRAN_AJAX', [
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('sadran_nonce')
        ]);

        wp_localize_script('sadran-admin-js', 'SADRAN_DATA', [
            'incidents' => get_option('sadran_incidents', []),
            'nonce'     => wp_create_nonce('sadran_nonce'),
        ]);
        // Chart.js from CDN (reliable, served via HTTPS)
        wp_enqueue_script('chartjs', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js', [], '4.4.0', true);

        // Dashboard controller
        wp_enqueue_script('sadran-dashboard-js', SADRAN_PLUGIN_URL . 'assets/js/dashboard.js', ['jquery','chartjs','sadran-admin-js'], '1.0', true);

    }


    /* ============================================================
       ADMIN DARK MODE
    ============================================================ */
    public function apply_dark_mode() {
        if (! get_option('sadran_ui_dark', 0)) return;

        echo '<style>
            body.wp-admin { background:#1e1e1e !important; color:#e0e0e0 !important; }
            .wrap, .sadran-card { background:#2a2a2a !important; color:#e0e0e0 !important; border-color:#444 !important; }
            .sadran-card h3, .sadran-card p { color:#f0f0f0 !important; }
            #adminmenu, #adminmenu .wp-submenu { background:#111 !important; }
            #adminmenu li.menu-top:hover, #adminmenu li.wp-has-current-submenu { background:#222 !important; }
        </style>';
    }

}
