<?php
// admin/tabs/overview.php
namespace SadranSecurity\Admin;

use SadranSecurity\Logging\LogsDB;

if (! defined('ABSPATH')) exit;

// Fetch plugin/state data
$db = LogsDB::instance();

// incidents and audit (fallbacks if AuditLogger missing)
$incidents = (array) get_option('sadran_incidents', []);
$blocked = (array) get_option('sadran_blocked_ips', []);
$last_scan = get_option('sadran_last_scan', 'Never');
$last_tamper = get_option('sadran_last_tamper_check', 'Never');

// try to get audit entries; if AuditLogger class missing, empty array
$audit = [];
if (class_exists('SadranSecurity\\Logging\\AuditLogger') && method_exists('\\SadranSecurity\\Logging\\AuditLogger', 'get')) {
    $audit = \SadranSecurity\Logging\AuditLogger::get(8);
}

// Compute a security score (simple heuristic)
$score = 92;
$score -= min(30, count($incidents) * 3);
$score -= min(20, count($blocked) * 2);
$score = max(6, $score);

// Hardening snapshot
$hardening = [
    'uploads_htaccess' => get_option('sadran_hardening_uploads_htaccess', 0),
    'disable_xmlrpc' => get_option('sadran_hardening_disable_xmlrpc', 0),
    'restrict_rest' => get_option('sadran_hardening_restrict_rest', 0),
    'block_bad_ua' => get_option('sadran_hardening_block_bad_ua', 0),
    'disable_file_edit' => get_option('sadran_hardening_disable_file_edit', 0),
];

// Pull recent logs (limit 50)
$logs = [];
if (method_exists($db, 'get_recent')) {
    $logs = $db->get_recent(50);
} elseif (method_exists($db, 'fetch')) {
    $logs = $db->fetch(50, 0);
}

// Build small aggregates for mini charts
$now = time();
$days = 14;
$labels = [];
$threats_by_day = array_fill(0, $days, 0);
for ($i = $days - 1; $i >= 0; $i--) {
    $t = strtotime("-{$i} days");
    $labels[] = date('M d', $t);
}
$severity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0];
$waf_counts = [];

foreach ($logs as $row) {
    // normalize timestamp
    $ts = null;
    if (!empty($row->time) && is_numeric($row->time)) $ts = intval($row->time);
    elseif (!empty($row->created_at)) $ts = strtotime($row->created_at);

    if ($ts) {
        $diffDays = floor(($now - $ts) / 86400);
        if ($diffDays >= 0 && $diffDays < $days) {
            $idx = $days - 1 - $diffDays;
            $threats_by_day[$idx]++;
        }
    }

    $sev = 1;
    if (isset($row->severity)) $sev = intval($row->severity);
    elseif (isset($row->level)) $sev = intval($row->level);

    if ($sev >= 3) $severity['critical']++;
    elseif ($sev == 2) $severity['high']++;
    elseif ($sev == 1) $severity['medium']++;
    else $severity['info']++;

    // WAF signature from meta if present
    $meta = null;
    if (!empty($row->meta)) {
        $meta = json_decode($row->meta, true);
    }
    if ($meta && !empty($meta['signature'])) {
        $sig = substr($meta['signature'], 0, 60);
        if (!isset($waf_counts[$sig])) $waf_counts[$sig] = 0;
        $waf_counts[$sig]++;
    } elseif ($row->type === 'waf_block') {
        $key = $row->message ?? 'waf_block';
        if (!isset($waf_counts[$key])) $waf_counts[$key] = 0;
        $waf_counts[$key]++;
    }
}

// Top WAF signature
arsort($waf_counts);
$waf_top = [];
if (!empty($waf_counts)) {
    $first_key = array_key_first($waf_counts);
    $waf_top = ['sig' => $first_key, 'count' => $waf_counts[$first_key]];
}

// Last 5 logs for quick listing
$recent_logs = array_slice($logs, 0, 5);

// Data blob for JS charts
$overview_js_data = [
    'labels' => $labels,
    'threats' => $threats_by_day,
    'severity' => array_values($severity), // [critical, high, medium, info]
];

?>

<div class="sadran-wrap sadran-overview">
    <h1>Sadran Security — Overview</h1>

    <div class="sadran-grid overview-grid">

        <!-- LEFT: Score + Quick stats -->
        <div class="sadran-left" style="flex:1.1">
            <div class="sadran-card score-card">
                <div class="score-left">
                    <canvas id="sadran-score-ring" width="160" height="160" aria-hidden="true"></canvas>
                </div>
                <div class="score-right">
                    <h2>Security Score</h2>
                    <div class="score-big"><?= esc_html($score); ?></div>
                    <p class="muted">Overall risk based on incidents and blocks.</p>
                    <p><strong>Blocked IPs:</strong> <?= count($blocked); ?> · <strong>Incidents:</strong> <?= count($incidents); ?></p>
                    <p><strong>Last scan:</strong> <?= esc_html($last_scan); ?></p>
                    <p><strong>Last tamper check:</strong> <?= esc_html($last_tamper); ?></p>
                </div>
            </div>

            <div class="sadran-card">
                <h3>Quick Actions</h3>
                <div style="display:flex;gap:8px;flex-wrap:wrap">
                    <button id="ov-run-scan" class="button button-primary">Run Full Scan</button>
                    <button id="ov-run-malware" class="button">Run Malware Scan</button>
                    <button id="ov-export-incidents" class="button">Export Incidents</button>
                    <button id="ov-apply-hardening" class="button button-secondary">Apply Hardening</button>
                </div>
            </div>

            <div class="sadran-card">
                <h3>WAF Snapshot</h3>
                <?php if (!empty($waf_top)): ?>
                    <p><strong>Top signature:</strong> <?= esc_html($waf_top['sig']); ?></p>
                    <p><strong>Hits:</strong> <?= intval($waf_top['count']); ?></p>
                <?php else: ?>
                    <p>No WAF blocks recorded recently.</p>
                <?php endif; ?>
            </div>

            <div class="sadran-card">
                <h3>Hardening Snapshot</h3>
                <ul class="hardening-list">
                    <li>Uploads HTAccess: <?= $hardening['uploads_htaccess'] ? '<span class="ok">On</span>' : '<span class="nok">Off</span>'; ?></li>
                    <li>Disable XML-RPC: <?= $hardening['disable_xmlrpc'] ? '<span class="ok">On</span>' : '<span class="nok">Off</span>'; ?></li>
                    <li>Restrict REST: <?= $hardening['restrict_rest'] ? '<span class="ok">On</span>' : '<span class="nok">Off</span>'; ?></li>
                    <li>Block bad UA: <?= $hardening['block_bad_ua'] ? '<span class="ok">On</span>' : '<span class="nok">Off</span>'; ?></li>
                    <li>Disable File Editor: <?= $hardening['disable_file_edit'] ? '<span class="ok">On</span>' : '<span class="nok">Off</span>'; ?></li>
                </ul>
            </div>
        </div>

        <!-- RIGHT: Mini charts + recent logs -->
        <div class="sadran-right" style="flex:1.6">
            <div class="sadran-card">
                <h3>Threats (Last 14 days)</h3>
                <canvas id="ov-threats-chart" height="120"></canvas>
                <div class="mini-stats" style="display:flex;gap:12px;margin-top:12px;">
                    <div><strong>Critical</strong><br><?= intval($severity['critical']); ?></div>
                    <div><strong>High</strong><br><?= intval($severity['high']); ?></div>
                    <div><strong>Medium</strong><br><?= intval($severity['medium']); ?></div>
                    <div><strong>Info</strong><br><?= intval($severity['info']); ?></div>
                </div>
            </div>

            <div class="sadran-card">
                <h3>Recent Activity (last <?= count($recent_logs); ?>)</h3>
                <?php if (!empty($recent_logs)): ?>
                    <div class="recent-list">
                        <?php foreach ($recent_logs as $r): ?>
                            <?php
                                $t = '';
                                if (!empty($r->time) && is_numeric($r->time)) $t = date('Y-m-d H:i:s', intval($r->time));
                                elseif (!empty($r->created_at)) $t = esc_html($r->created_at);
                                else $t = '-';
                            ?>
                            <div class="recent-row" data-log='<?= esc_attr(json_encode($r, JSON_HEX_APOS | JSON_HEX_QUOT)); ?>'>
                                <div class="rr-left"><strong><?= esc_html(strtoupper($r->type ?? 'log')); ?></strong></div>
                                <div class="rr-mid"><?= esc_html(mb_strimwidth($r->message ?? '', 0, 120, '...')); ?></div>
                                <div class="rr-right"><?= esc_html($t); ?></div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p>No recent logs.</p>
                <?php endif; ?>
            </div>

            <div class="sadran-card recommended-card">
                <h3>Recommended Actions</h3>
                <ul>
                    <?php
                        // Simple recommendations
                        if (count($incidents) > 0) {
                            echo '<li><strong>Review incidents</strong> — there are ' . count($incidents) . ' recorded incidents.</li>';
                        }
                        if (! $hardening['uploads_htaccess']) {
                            echo '<li><strong>Deploy uploads .htaccess</strong> — prevent PHP execution in uploads.</li>';
                        }
                        if (! $hardening['disable_file_edit']) {
                            echo '<li><strong>Disable File Editor</strong> — prevents code edits via wp-admin.</li>';
                        }
                        if (empty($blocked)) {
                            echo '<li>No blocked IPs — consider enabling login rate limiting if under attack.</li>';
                        }
                    ?>
                </ul>
            </div>
        </div>
    </div>
</div>

<style>
/* Overview layout */
.sadran-overview .overview-grid { display:flex; gap:18px; align-items:flex-start; }
.sadran-card.score-card { display:flex; gap:12px; align-items:center; padding:18px; }
.score-left { width:160px; height:160px; display:flex; align-items:center; justify-content:center; }
.score-right { flex:1; }
.score-big { font-size:36px; font-weight:700; margin:6px 0; }
.hardening-list { list-style:none; padding:0; margin:0; }
.hardening-list li { margin-bottom:6px; }
.ok { color:#16a34a; font-weight:700; }
.nok { color:#d33; font-weight:700; }

.recent-list { display:flex; flex-direction:column; gap:8px; }
.recent-row { display:flex; gap:10px; padding:8px; border-radius:6px; background:#0f1720; align-items:center; cursor:pointer; }
.recent-row .rr-left { width:110px; font-size:12px; color:#9aa6b2; }
.recent-row .rr-mid { flex:1; color:#e6eef6; font-size:13px; }
.recent-row .rr-right { width:160px; text-align:right; color:#9aa6b2; font-size:12px; }

.recommended-card ul { list-style:disc; margin-left:18px; }

@media (max-width:1000px) {
    .sadran-overview .overview-grid { flex-direction:column; }
}

/* Reduce mini threats chart size */
#ov-threats-chart {
    max-height: 80px !important;
    height: 80px !important;
}

/* Reduce card padding so the chart card is smaller */
.sadran-card canvas {
    margin-top: 5px;
}

.sadran-card {
    padding: 12px !important;
}
</style>

<script>
(function(){
    // data passed to JS
    var data = <?= json_encode($overview_js_data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;

    // draw simple ring (score) using Chart.js if available, else fallback to text
    var score = <?= intval($score); ?>;
    function drawScore() {
        if (typeof Chart === 'undefined') {
            return;
        }
        var ctx = document.getElementById('sadran-score-ring').getContext('2d');
        var remaining = 100 - score;
        // use doughnut
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Score','Remaining'],
                datasets: [{
                    data: [score, remaining],
                    borderWidth: 0,
                    backgroundColor: ['#3de2ff', '#263238']
                }]
            },
            options: {
                cutout: '70%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });

        // overlay the number
        var canvas = document.getElementById('sadran-score-ring');
        var ctx2 = canvas.getContext('2d');
        ctx2.font = "20px Arial";
        ctx2.fillStyle = "#ffffff";
        ctx2.textAlign = "center";
        ctx2.textBaseline = "middle";
        ctx2.fillText(score + "%", canvas.width/2, canvas.height/2);
    }

    function drawThreatsMini() {
        if (typeof Chart === 'undefined') return;
        var ctx = document.getElementById('ov-threats-chart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Threats',
                    data: data.threats,
                    fill: true,
                    tension: 0.3,
                    borderWidth: 1,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display:false }, tooltip: { mode: 'index', intersect: false } },
                scales: {
                    x: { display: false },
                    y: { display: false }
                }
            }
        });
    }

    // wire quick actions
    jQuery(function($){
        drawScore();
        drawThreatsMini();

        $('#ov-run-scan').on('click', function(e){
            e.preventDefault();
            $('#ov-run-scan').prop('disabled', true).text('Running...');
            $.post(SADRAN_AJAX.ajaxurl, { action: 'sadran_run_scan', _wpnonce: SADRAN_AJAX.nonce }, function(res){
                if (res.success) {
                    $('#ov-run-scan').text('Run Full Scan');
                    alert('Integrity scan queued/completed.');
                    location.reload();
                } else {
                    alert('Scan failed: ' + (res.data || 'unknown'));
                    $('#ov-run-scan').prop('disabled', false).text('Run Full Scan');
                }
            }).fail(function(){ alert('Network error'); $('#ov-run-scan').prop('disabled', false).text('Run Full Scan'); });
        });

        $('#ov-run-malware').on('click', function(e){
            e.preventDefault();
            $('#ov-run-malware').prop('disabled', true).text('Scanning...');
            $.post(SADRAN_AJAX.ajaxurl, { action: 'sadran_run_malware', _wpnonce: SADRAN_AJAX.nonce }, function(res){
                if (res.success) {
                    alert('Malware scan finished.');
                    location.reload();
                } else {
                    alert('Malware scan failed: ' + (res.data || 'missing'));
                    $('#ov-run-malware').prop('disabled', false).text('Run Malware Scan');
                }
            }).fail(function(){ alert('Network error'); $('#ov-run-malware').prop('disabled', false).text('Run Malware Scan'); });
        });

        $('#ov-export-incidents').on('click', function(e){
            e.preventDefault();
            var incidents = <?= json_encode($incidents, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT); ?> || [];
            var blob = new Blob([JSON.stringify(incidents, null, 2)], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url; a.download = 'sadran-incidents.json'; document.body.appendChild(a); a.click(); a.remove();
        });

        $('#ov-apply-hardening').on('click', function(e){
            e.preventDefault();
            var btn = $(this); btn.text('Applying...');
            $.post(SADRAN_AJAX.ajaxurl, { action: 'sadran_apply_hardening', _wpnonce: SADRAN_AJAX.nonce }, function(res){
                if (res.success) { alert('Hardening applied.'); location.reload(); }
                else { alert('Failed: ' + (res.data || 'unknown')); btn.text('Apply Hardening'); }
            }).fail(function(){ alert('Network error'); btn.text('Apply Hardening'); });
        });

        // row click -> open modal (reuse dashboard modal if present)
        $('.recent-row').on('click', function(){
            var raw = $(this).attr('data-log');
            if (!raw) return;
            try {
                var obj = JSON.parse(raw);
                var modal = jQuery('#sadran-log-modal');
                if (!modal.length) {
                    alert(JSON.stringify(obj, null, 2));
                    return;
                }
                jQuery('#modal-type').text((obj.type || 'Log').toUpperCase());
                jQuery('#modal-message').text(obj.message || '');
                jQuery('#modal-meta').text(JSON.stringify(obj, null, 2));
                modal.fadeIn(150);
            } catch (e) {
                console.error(e);
            }
        });

        // close modal handlers (if present)
        jQuery('.sadran-modal-close, #modal-close-btn').on('click', function(){ jQuery('#sadran-log-modal').fadeOut(120); });
    });

})();
</script>
