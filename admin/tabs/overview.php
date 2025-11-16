<div class="sadran-section">
    <h2>System Overview</h2>

    <div class="sadran-card">
        <p>Status: <strong>Operational</strong></p>
        <p>Recent Incidents: <?= count((array)get_option('sadran_incidents',[])) ?></p>

        <button class="button button-primary" id="sadran-run-scan">Run Integrity Scan</button>
        <div id="sadran-scan-result"></div>
    </div>
</div>
