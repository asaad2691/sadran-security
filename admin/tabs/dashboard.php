<?php
use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;
?>

<div class="sadran-section">
    <h2>Sadran Security Dashboard</h2>
    <p class="subtle">Live security overview — charts & recent activity</p>

    <div id="sadran-dashboard-loading" class="loading-box">Loading dashboard…</div>

    <div id="sadran-dashboard" style="display:none">

        <!-- TOP ROW: CARDS -->
        <div class="sadran-grid">
            <div class="sadran-card stat" id="stat-total-logs">
                <h3>Total Logs</h3>
                <span class="big-number">0</span>
            </div>

            <div class="sadran-card stat" id="stat-last-activity">
                <h3>Last Activity</h3>
                <span class="big-number">–</span>
            </div>

            <div class="sadran-card stat" id="stat-health">
                <h3>System Health</h3>
                <span class="status-green">Optimal</span>
            </div>
        </div>

        <br>

        <!-- ACTIONS -->
        <div class="sadran-btn-row">
            <button id="dash-run-scan" class="button button-primary">Run Integrity Scan</button>
            <button id="dash-run-malware" class="button button-secondary">Run Malware Scan</button>
            <button id="dash-clear-logs" class="button button-danger">Clear Logs</button>
            <button id="dash-reload" class="button">Reload Dashboard</button>
        </div>

        <br>

        <!-- CHARTS ROW -->
        <div class="sadran-grid" style="align-items:stretch;">
            <div class="sadran-card" style="flex:2">
                <h3>Threats Per Day (last 30 days)</h3>
                <canvas id="chart-threats-day" height="160"></canvas>
            </div>

            <div class="sadran-card" style="flex:1">
                <h3>Severity Breakdown</h3>
                <canvas id="chart-severity" height="160"></canvas>
            </div>
        </div>

        <br>

        <div class="sadran-card">
            <h3>WAF Blocks by Signature</h3>
            <canvas id="chart-waf" height="120"></canvas>
        </div>

        <br>

        <!-- LOG FEED -->
        <h3>Recent Activity</h3>
        <div class="sadran-filter-bar">
    
            <select id="filter-type">
                <option value="">All Types</option>
                <option value="file_scan">File Scan</option>
                <option value="malware_scan">Malware Scan</option>
                <option value="plugin_tamper">Plugin Tamper</option>
                <option value="waf_block">WAF Blocks</option>
                <option value="login_fail">Login Failures</option>
            </select>

            <select id="filter-severity">
                <option value="">All Severity</option>
                <option value="3">Critical</option>
                <option value="2">High</option>
                <option value="1">Medium</option>
                <option value="0">Info</option>
            </select>

            <select id="filter-range">
                <option value="1">Last 24 Hours</option>
                <option value="7">Last 7 Days</option>
                <option value="30" selected>Last 30 Days</option>
                <option value="custom">Custom Range</option>
            </select>

            <input type="date" id="filter-start" style="display:none;">
            <input type="date" id="filter-end" style="display:none;">

            <input type="text" id="filter-search" placeholder="Search logs…">

            <button id="filter-clear" class="button">Reset</button>
        </div>

        <hr>

        <div id="sadran-dashboard-feed" class="sadran-feed"></div>
        <div class="sadran-pagination">
            <button id="page-prev" class="button">Prev</button>
            <span id="page-info">Page 1</span>
            <button id="page-next" class="button">Next</button>
        </div>

        <style>
        .sadran-pagination {
            margin-top: 15px;
            display:flex;
            gap:10px;
            align-items:center;
        }
        </style>

    </div>
</div>
<div id="sadran-log-modal" class="sadran-modal" style="display:none;">
    <div class="sadran-modal-content">
        <span class="sadran-modal-close">&times;</span>

        <h2 id="modal-type"></h2>
        <p id="modal-message"></p>

        <hr>

        <h3>Details:</h3>
        <pre id="modal-meta"></pre>

        <div class="modal-actions">
            <button class="button button-secondary" id="modal-copy">Copy JSON</button>
            <button class="button" id="modal-close-btn">Close</button>
        </div>
    </div>
</div>
<style>
/* Reduce chart container height and auto-adjust */
#chart-threats-day,
#chart-severity,
#chart-waf {
    max-height: 240px !important;
}

/* Make card force a limit so canvas shrinks too */
.sadran-card canvas {
    max-height: 240px !important;
}
</style>

<style>
.sadran-modal {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0,0,0,0.70);
    z-index: 99999;
}
.sadran-modal-content {
    background: #1f1f1f;
    padding: 20px;
    width: 600px;
    margin: 80px auto;
    border-radius: 8px;
    color: #fff;
}
.sadran-modal-close {
    float:right;
    cursor:pointer;
    font-size:24px;
}
</style>
<style>
.loading-box { padding:20px; text-align:center; font-size:18px; }
.sadran-grid { display:flex; gap:20px; }
.sadran-card.stat { flex:1; text-align:center; }
.big-number { font-size:32px; font-weight:bold; }
.status-green { color:#0f0; } .status-red { color:#f33; }
.sadran-feed-row { background:#111; padding:12px; margin-bottom:10px; border-radius:6px; border-left:4px solid #3fa9f5; }
.feed-time { color:#bbb; font-size:12px; }
.sadran-filter-bar {
    display:flex;
    gap:10px;
    margin-bottom:15px;
    flex-wrap:wrap;
}
.sadran-filter-bar select,
.sadran-filter-bar input {
    padding:5px 8px;
}


.sadran-feed-row {
    padding: 12px;
    margin-bottom: 10px;
    border-radius: 6px;
    background: #111;
    border-left: 5px solid #3fa9f5;
    cursor: pointer;
    transition: background 0.2s ease;
}
.sadran-feed-row:hover {
    background: #181818;
}

/* Severity colors */
.sev-critical { border-color: #e53935; }
.sev-high     { border-color: #fb8c00; }
.sev-medium   { border-color: #fdd835; }
.sev-info     { border-color: #42a5f5; }

</style>
