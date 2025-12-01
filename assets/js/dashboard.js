jQuery(function($) {

    /* -----------------------------------------------------
       Chart instances
    ----------------------------------------------------- */
    let threatsChart = null,
        severityChart = null,
        wafChart = null;

    let sadran_last_log_id = 0; // still stored for modal / reference, but no polling
    let currentPage = 1;
    let totalPages = 1;

    /* -----------------------------------------------------
       Build Charts
    ----------------------------------------------------- */
    function buildCharts(data) {
        const ctx1 = document.getElementById('chart-threats-day').getContext('2d');
        if (threatsChart) threatsChart.destroy();
        threatsChart = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: data.threats_by_day.labels,
                datasets: [{
                    label: 'Threats',
                    data: data.threats_by_day.values,
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });

        const ctx2 = document.getElementById('chart-severity').getContext('2d');
        if (severityChart) severityChart.destroy();
        severityChart = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Info'],
                datasets: [{
                    data: [data.severity.critical, data.severity.high, data.severity.medium, data.severity.info],
                    borderWidth: 1
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        const ctx3 = document.getElementById('chart-waf').getContext('2d');
        if (wafChart) wafChart.destroy();
        wafChart = new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: data.waf_labels,
                datasets: [{ label: 'Blocks', data: data.waf_values, borderWidth: 1 }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
        });
    }

    /* -----------------------------------------------------
       Render Feed + Modal Binding
    ----------------------------------------------------- */
    function renderFeed(logs, prepend = false) {
        let feedHTML = '';

        logs.forEach(function(row) {
            let t = row.time || row.created_at || '';
            if (/^\d+$/.test(String(t)))
                t = new Date(parseInt(t, 10) * 1000).toISOString().replace('T', ' ').slice(0, 19);

            let sev = parseInt(row.severity || 0, 10);
            let sevClass = 'sev-info';
            if (sev >= 3) sevClass = 'sev-critical';
            else if (sev === 2) sevClass = 'sev-high';
            else if (sev === 1) sevClass = 'sev-medium';

            let icon = 'ℹ️';
            switch (row.type) {
                case 'malware_scan':
                    icon = '🐞';
                    break;
                case 'file_scan':
                    icon = '💾';
                    break;
                case 'plugin_tamper':
                    icon = '🔧';
                    break;
                case 'waf_block':
                    icon = '🛡️';
                    break;
                case 'login_fail':
                    icon = '🔑';
                    break;
            }

            let encoded = JSON.stringify(row)
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');

            feedHTML += `
                <div class="sadran-feed-row ${sevClass}" data-log="${encoded}" data-log-id="${row.id}">
                    <strong>${icon} ${row.type.toUpperCase()}</strong> — ${row.message}
                    <br><span class="feed-time">${t}</span>
                </div>
            `;
        });

        if (prepend) {
            $('#sadran-dashboard-feed').prepend(feedHTML);
        } else {
            $('#sadran-dashboard-feed').html(feedHTML);
        }

        bindRowClicks();
    }

    function bindRowClicks() {
        $('.sadran-feed-row').off('click').on('click', function() {
            let raw = $(this).data('log');
            if (!raw) return;

            let log = typeof raw === 'string' ? JSON.parse(raw) : raw;
            $('#modal-type').text(log.type ? log.type.toUpperCase() : 'Log Entry');
            $('#modal-message').text(log.message || '');
            $('#modal-meta').text(JSON.stringify(log, null, 2));
            $('#sadran-log-modal').fadeIn(150);
        });

        $('.sadran-modal-close, #modal-close-btn').off('click').on('click', function() {
            $('#sadran-log-modal').fadeOut(100);
        });

        $('#modal-copy').off('click').on('click', function() {
            navigator.clipboard.writeText($('#modal-meta').text());
            alert('Copied to clipboard');
        });
    }

    /* -----------------------------------------------------
       Load Dashboard (ONE-TIME or Manual Reload)
    ----------------------------------------------------- */
    function loadDashboard(page = 1) {
        currentPage = page;

        $('#sadran-dashboard-loading').show();
        $('#sadran-dashboard').hide();

        $.post(SADRAN_AJAX.ajaxurl, {
                action: 'sadran_dashboard_data',
                _wpnonce: SADRAN_AJAX.nonce,
                page: page
            })
            .done(function(res) {
                if (!res.success) {
                    $('#sadran-dashboard-loading').text('Error loading dashboard');
                    return;
                }

                const data = res.data;

                totalPages = data.total_pages || 1;

                $('#page-info').text(`Page ${currentPage} of ${totalPages}`);
                $('#page-prev').prop('disabled', currentPage <= 1);
                $('#page-next').prop('disabled', currentPage >= totalPages);

                // Stats + charts
                $('#stat-total-logs .big-number').text(data.total);
                buildCharts(data);
                renderFeed(data.logs);

                $('#sadran-dashboard-loading').hide();
                $('#sadran-dashboard').fadeIn(200);
            });
    }
    $('#page-prev').on('click', function() {
        if (currentPage > 1) {
            loadDashboard(currentPage - 1);
        }
    });

    $('#page-next').on('click', function() {
        if (currentPage < totalPages) {
            loadDashboard(currentPage + 1);
        }
    });


    /* -----------------------------------------------------
       Filters
    ----------------------------------------------------- */
    function runFilters() {
        let type = $('#filter-type').val();
        let severity = $('#filter-severity').val();
        let range = $('#filter-range').val();
        let search = $('#filter-search').val();
        let start = $('#filter-start').val();
        let end = $('#filter-end').val();

        if (range !== 'custom') {
            start = end = '';
        } else {
            range = -1;
        }

        $.post(SADRAN_AJAX.ajaxurl, {
            action: 'sadran_filter_logs',
            _wpnonce: SADRAN_AJAX.nonce,
            type: type,
            severity: severity,
            range: range,
            search: search,
            start: start,
            end: end
        }, function(res) {
            if (res.success) renderFeed(res.data);
        });
    }

    /* -----------------------------------------------------
       UI Bindings
    ----------------------------------------------------- */
    $('#dash-clear-logs').on('click', function() {
        if (!confirm('Clear all logs?')) return;
        $.post(SADRAN_AJAX.ajaxurl, { action: 'sadran_clear_logs', _wpnonce: SADRAN_AJAX.nonce })
            .done(loadDashboard);
    });

    $('#dash-run-scan').on('click', () => $('#sadran-run-scan').trigger('click'));
    $('#dash-run-malware').on('click', () => $('#sadran-run-malware').trigger('click'));

    // NEW: Manual reload button
    $('#dash-reload').on('click', function() {
        loadDashboard();
    });

    $('#filter-type').on('change', runFilters);
    $('#filter-severity').on('change', runFilters);

    $('#filter-range').on('change', function() {
        if ($(this).val() === 'custom') {
            $('#filter-start, #filter-end').show();
        } else {
            $('#filter-start, #filter-end').hide();
            runFilters();
        }
    });

    $('#filter-start, #filter-end').on('change', runFilters);
    $('#filter-search').on('keyup', runFilters);

    $('#filter-clear').on('click', function() {
        $('#filter-type').val('');
        $('#filter-severity').val('');
        $('#filter-range').val('30');
        $('#filter-search').val('');
        $('#filter-start, #filter-end').hide().val('');
        loadDashboard();
    });

    /* -----------------------------------------------------
       INITIAL LOAD (No realtime)
    ----------------------------------------------------- */
    loadDashboard();
});