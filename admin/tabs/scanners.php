<?php
use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

// Fetch logs
$logs = LogsDB::instance()->get_recent(200);

// Buckets
$file_changes = [];
$malware_hits = [];
$tamper_hits = [];

foreach ($logs as $log) {
    switch ($log->type) {
        case 'file_scan':
            $file_changes[] = $log;
            break;

        case 'malware_scan':
            $malware_hits[] = $log;
            break;

        case 'plugin_tamper':
            $tamper_hits[] = $log;
            break;
    }
}

$last_file_scan    = $file_changes[0]->time ?? 'Never';
$last_malware_scan = $malware_hits[0]->time ?? 'Never';
$last_tamper_scan  = $tamper_hits[0]->time ?? 'Never';
?>

<div class="sadran-section">
    <h2>Scanners</h2>

    <!-- FILE INTEGRITY -->
    <div class="sadran-card">
        <h3>File Integrity Scanner</h3>
        <p>Checks plugins, themes, and core for changes.</p>

        <button class="button button-primary" id="sadran-run-scan">
            Run Integrity Scan
        </button>

        <div id="sadran-scan-result" class="sadran-scan-output"></div>

        <hr>
        <h4>Last Scan: <?= esc_html($last_file_scan); ?></h4>

        <?php if (!empty($file_changes)): ?>
            <ul class="sadran-log-list">

                <?php foreach ($file_changes as $row): ?>
                    <li>
                        <strong><?= esc_html(date('Y-m-d H:i:s', $row->time)); ?></strong><br>
                        <?= esc_html($row->message); ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No file integrity issues detected.</p>
        <?php endif; ?>
    </div>


    <!-- MALWARE SCANNER -->
    <div class="sadran-card">
        <h3>Malware Scanner</h3>
        <p>Scans uploads, plugins, and themes for malware.</p>

        <button class="button button-secondary" id="sadran-run-malware">
            Run Malware Scan
        </button>

        <div id="sadran-malware-result" class="sadran-scan-output"></div>

        <hr>
        <h4>Last Scan: <?= esc_html($last_malware_scan); ?></h4>

        <?php if (!empty($malware_hits)): ?>
            <ul class="sadran-log-list">
                <?php foreach ($malware_hits as $row): ?>
                    <li>
                        <strong><?= esc_html(date('Y-m-d H:i:s', $row->time)); ?></strong><br>
                        <?= esc_html($row->message); ?>
                        <?php if (!empty($row->meta)): ?>
                            <pre class="sadran-json"><?= esc_html($row->meta); ?></pre>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No malware detected.</p>
        <?php endif; ?>
    </div>


    <!-- PLUGIN TAMPER -->
    <div class="sadran-card">
        <h3>Plugin Tamper Scanner</h3>
        <p>Detects suspicious or tampered plugins.</p>

        <h4>Last Check: <?= esc_html($last_tamper_scan); ?></h4>

        <?php if (!empty($tamper_hits)): ?>
            <ul class="sadran-log-list">
                <?php foreach ($tamper_hits as $row): ?>
                    <li>
                        <strong><?= esc_html(date('Y-m-d H:i:s', $row->time)); ?></strong><br>
                        <?= esc_html($row->message); ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No plugin tampering detected.</p>
        <?php endif; ?>
    </div>
    
</div>

<style>
.sadran-scan-output { margin-top:10px; font-weight:bold; }
.sadran-log-list { margin-left:15px; padding-left:10px; border-left:2px solid #444; }
.sadran-log-list li { margin-bottom:10px; }
.sadran-json { background:#111; padding:8px; margin-top:5px; border-radius:4px; font-size:12px; }
</style>
