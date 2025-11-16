<?php
// Dashboard Overview UI
$incidents = (array) get_option('sadran_incidents', []);
$audit = \SadranSecurity\Logging\AuditLogger::get(10);

// Compute a simple security score
$score = 90;
$score -= min(30, count($incidents) * 3);
$blocked = (array) get_option('sadran_blocked_ips', []);
$score -= min(20, count($blocked) * 2);
$score = max(10, $score);

// mode
$dark = get_option('sadran_ui_dark', 0);
?>
<div class="sadran-wrap">
    <h1><?php esc_html_e('Sadran Security', 'sadran-security'); ?></h1>

    <div class="sadran-dashboard">
        <div class="sadran-left">
            <div class="sadran-card score-card">
                <h2>Security Score</h2>
                <div class="score-ring">
                    <div class="score-number"><?= esc_html($score) ?></div>
                </div>
                <p class="muted">Overall risk assessment based on incidents and blocks.</p>
            </div>

            <div class="sadran-card">
                <h3>Threat Overview</h3>
                <p>Recent incidents: <strong><?= count($incidents) ?></strong></p>
                <p>Blocked IPs: <strong><?= count($blocked) ?></strong></p>
                <p>Last audit events:</p>
                <ul>
                    <?php foreach ($audit as $a): ?>
                        <li><strong><?= date('Y-m-d H:i:s', $a['t']) ?></strong> — <?= esc_html($a['type']) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>

        <div class="sadran-right">
            <div class="sadran-card">
                <h3>Quick Actions</h3>
                <p>
                    <button id="sadran-run-scan" class="button button-primary">Run File Integrity Scan</button>
                    <button id="sadran-export-log" class="button">Export Incidents</button>
                </p>
                <div id="sadran-scan-result"></div>
            </div>

            <div class="sadran-card">
                <h3>Settings Snapshot</h3>
                <ul>
                    <li>Uploads HTAccess: <?= get_option('sadran_hardening_uploads_htaccess', 0) ? 'On' : 'Off' ?></li>
                    <li>Disable XML-RPC: <?= get_option('sadran_hardening_disable_xmlrpc', 0) ? 'On' : 'Off' ?></li>
                    <li>Restrict REST API: <?= get_option('sadran_hardening_restrict_rest', 0) ? 'On' : 'Off' ?></li>
                </ul>
            </div>
        </div>
    </div>
</div>
