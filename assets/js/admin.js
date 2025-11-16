jQuery(function($) {
    $('#sadran-run-scan').on('click', function(e) {
        e.preventDefault();
        $('#sadran-scan-result').text('Running scan...');
        $.post(ajaxurl, {
            action: 'sadran_run_scan',
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res) {
            if (res.success) $('#sadran-scan-result').html('<strong>Scan completed.</strong>');
            else $('#sadran-scan-result').text('Error: ' + res.data);
        });
    });

    $('#sadran-export-log').on('click', function(e) {
        e.preventDefault();
        var incidents = <?php
            $inc = (array) get_option('sadran_incidents',[]);
            echo json_encode($inc);
        ?>;
        var blob = new Blob([JSON.stringify(incidents, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'sadran-incidents.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
    });

    // dark mode toggle: body class applied server-side; small toggle via JS if needed.
});