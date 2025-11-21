<?php
use SadranSecurity\Scanners\FileIntegrityScanner;
use SadranSecurity\Scanners\PluginTamperScanner;

if (!defined('ABSPATH')) exit;

// Load last scan results
$incidents = get_option('sadran_incidents', []);
$last_scan = get_option('sadran_last_scan', 'Never');

// Parse file integrity results
$last_file_scan = $incidents['file_integrity'] ?? [];
$modified = $last_file_scan['modified'] ?? [];
$added    = $last_file_scan['added'] ?? [];
$removed  = $last_file_scan['missing'] ?? [];
?>

<div class="sadran-section">
    <h2>Scanners</h2>

    <!-- FILE INTEGRITY SCANNER -->
    <div class="sadran-card">
        <h3>File Integrity Scanner</h3>
        <p>Checks core, plugin and theme files for tampering.</p>

        <button class="button button-primary" id="sadran-run-scan">
            Run Full Scan
        </button>

        <div id="sadran-scan-result" style="margin-top:10px; font-weight:bold;"></div>

        <hr>

        <h4>Last Scan: <?= esc_html($last_scan); ?></h4>

        <?php if (!empty($modified) || !empty($added) || !empty($removed)): ?>
            <div class="sadran-scan-summary">

                <?php if (!empty($modified)): ?>
                    <h5>Modified Files</h5>
                    <ul>
                    <?php foreach ($modified as $file): ?>
                        <li style="color:#c0392b;">⚠ <?= esc_html($file); ?></li>
                    <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($added)): ?>
                    <h5>New/Suspicious Files</h5>
                    <ul>
                    <?php foreach ($added as $file): ?>
                        <li style="color:#f39c12;">⚠ <?= esc_html($file); ?></li>
                    <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

                <?php if (!empty($removed)): ?>
                    <h5>Missing Files</h5>
                    <ul>
                    <?php foreach ($removed as $file): ?>
                        <li style="color:#8e44ad;">⚠ <?= esc_html($file); ?></li>
                    <?php endforeach; ?>
                    </ul>
                <?php endif; ?>

            </div>
        <?php else: ?>
            <p>No threats detected in last scan.</p>
        <?php endif; ?>
    </div>

    <!-- PLUGIN TAMPER SCANNER -->
    <div class="sadran-card">
        <h3>Plugin Tamper Scanner</h3>
        <p>Automatically compares plugin files to detect unauthorized changes.</p>

        <h4>Last Tamper Check:</h4>
        <p><?= esc_html(get_option('sadran_last_tamper_check', 'Runs automatically')); ?></p>

        <?php
        $tamper_incidents = $incidents['plugin_tamper'] ?? [];
        if (!empty($tamper_incidents)):
        ?>
            <h5>Detected Issues</h5>
            <ul>
            <?php foreach ($tamper_incidents as $issue): ?>
                <li style="color:#e74c3c;">⚠ <?= esc_html($issue); ?></li>
            <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No plugin tampering detected.</p>
        <?php endif; ?>
    </div>
</div>

<style>
.sadran-card ul {
    margin-left: 20px;
}
.sadran-card li {
    margin-bottom: 3px;
}
</style>
