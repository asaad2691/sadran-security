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
                    <?php 
                    $meta_raw = $row->meta ?: $row->extra_json;
                    $meta_safe = '';

                    if (!empty($meta_raw)) {
                        // Decode → Re-encode cleanly
                        $decoded = json_decode($meta_raw, true);
                        if (json_last_error() === JSON_ERROR_NONE) {
                            $meta_safe = wp_json_encode($decoded);
                        }
                    }
                    ?>
                        <strong><?= esc_html(date('Y-m-d H:i:s', $row->time)); ?></strong><br>
                        <?= esc_html($row->message); ?>

                        <?php if (!empty($meta_safe)): ?>
                            <button 
                                class="button button-small view-malware" 
                                data-json="<?= esc_attr($meta_safe); ?>"
                            >
                                View Details
                            </button>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php else: ?>
            <p>No malware detected.</p>
        <?php endif; ?>
    </div>


    <!-- PLUGIN TAMPER SCANNER -->
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


<!-- MALWARE DETAILS MODAL -->
<div id="malware-modal" class="sadran-modal" style="display:none;">
    <div class="sadran-modal-content">
        <span class="sadran-modal-close">&times;</span>

        <h2 id="malware-file"></h2>
        <p><strong>Score:</strong> <span id="malware-score"></span></p>

        <h3>Matches</h3>
        <pre id="malware-matches"></pre>

        <h3>Entropy</h3>
        <p id="malware-entropy"></p>

        <div class="modal-actions">
            <button class="button button-secondary" id="malware-quarantine">Quarantine File</button>
            <button class="button button-secondary" id="malware-delete">Delete File</button>
            <button class="button" id="malware-close-btn">Close</button>
        </div>
    </div>
</div>


<style>
.sadran-scan-output { margin-top:10px; font-weight:bold; }
.sadran-log-list { margin-left:15px; padding-left:10px; border-left:2px solid #444; }
.sadran-log-list li { margin-bottom:10px; }
.sadran-json { background:#111; padding:8px; margin-top:5px; border-radius:4px; font-size:12px; }

/* Modal */
.sadran-modal {
    position: fixed;
    top:0; left:0;
    width:100%; height:100%;
    background: rgba(0,0,0,0.7);
    z-index: 999999;
}
.sadran-modal-content {
    background:#1e1e1e;
    padding:20px;
    width:650px;
    margin:100px auto;
    border-radius:8px;
    color:#fff !important;
}
.sadran-modal-content h2, .sadran-modal-content h3 {
    color: #fff !important;
}
.sadran-modal-close {
    float:right;
    cursor:pointer;
    font-size:24px;
}
</style>

<script>
function decodeHtmlEntities(str) {
    return jQuery("<textarea/>").html(str).text();
}

jQuery(function($) {

    $(".view-malware").on("click", function() {

        let raw = $(this).data("json");
        let meta = null;

        try {

            if (typeof raw === "object") {
                // Already decoded & parsed
                meta = raw;

            } else if (typeof raw === "string") {
                // Decode HTML entities → parse JSON
                let decoded = decodeHtmlEntities(raw.trim());

                if (decoded.startsWith("{") && decoded.endsWith("}")) {
                    meta = JSON.parse(decoded);
                } else {
                    console.error("Invalid JSON string:", decoded);
                    alert("Meta JSON invalid");
                    return;
                }

            } else {
                alert("Meta JSON invalid");
                return;
            }

        } catch (e) {
            console.error("Parse error:", e, raw);
            alert("Meta JSON invalid");
            return;
        }

        // Populate modal fields
        $("#malware-file").text(meta.file || "Unknown file");
        $("#malware-score").text(meta.score || 0);
        $("#malware-entropy").text(meta.entropy || "N/A");
        $("#malware-matches").text(JSON.stringify(meta.matches || {}, null, 2));

        $("#malware-modal").fadeIn(150);
    });

    $(".sadran-modal-close, #malware-close-btn").on("click", function(){
        $("#malware-modal").fadeOut(100);
    });

});
</script>
<script>
jQuery(function($){

    let selectedFile = null;

    // When user clicks "View Details"
    $(".view-malware").on("click", function() {

        let raw = $(this).data("json");

        try {
            let meta = typeof raw === 'object' ? raw : JSON.parse(raw);

            selectedFile = meta.file || null;

            $("#malware-file").text(meta.file || "Unknown file");
            $("#malware-score").text(meta.score || 0);
            $("#malware-entropy").text(meta.entropy || "N/A");
            $("#malware-matches").text(JSON.stringify(meta.matches || {}, null, 2));

            $("#malware-modal").fadeIn(150);

        } catch (e) {
            console.error(e);
            alert("Meta JSON invalid");
        }
    });

    // Close modal
    $(".sadran-modal-close, #malware-close-btn").on("click", function(){
        $("#malware-modal").fadeOut(100);
    });

    // -------------------------------
    // Quarantine File
    // -------------------------------
    $("#malware-quarantine").on("click", function(){

        if (!selectedFile) {
            alert("No file selected.");
            return;
        }

        $.post(ajaxurl, {
            action: "sadran_malware_quarantine",
            file: selectedFile,
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res){
            if (res.success) {
                alert("File quarantined successfully");
                $("#malware-modal").fadeOut(100);
            } else {
                alert("Error: " + res.data);
            }
        });
    });

    // -------------------------------
    // Delete File
    // -------------------------------
    $("#malware-delete").on("click", function(){

        if (!confirm("Are you sure? This cannot be undone.")) return;

        if (!selectedFile) {
            alert("No file selected.");
            return;
        }

        $.post(ajaxurl, {
            action: "sadran_malware_delete",
            file: selectedFile,
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res){
            if (res.success) {
                alert("File deleted successfully");
                $("#malware-modal").fadeOut(100);
            } else {
                alert("Error: " + res.data);
            }
        });
    });

});
</script>
