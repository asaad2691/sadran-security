jQuery(function($) {

    /* ------------------------------
       FILE INTEGRITY SCAN
    ------------------------------ */
    $('#sadran-run-scan').on('click', function(e) {
        e.preventDefault();

        $('#sadran-scan-result')
            .text('Running integrity scan...')
            .css({ 'color': '#888' });

        $.post(SADRAN_AJAX.ajaxurl, {
            action: 'sadran_run_scan',
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res) {
            if (res.success) {
                $('#sadran-scan-result')
                    .html('<strong>Integrity scan completed.</strong>')
                    .css({ 'color': '#0a0' });

                console.log('Integrity Scan Result:', res.data);
            } else {
                $('#sadran-scan-result')
                    .text('Error: ' + res.data)
                    .css({ 'color': '#c00' });
            }
        });
    });


    /* ------------------------------
       MALWARE SCAN
    ------------------------------ */
    $('#sadran-run-malware').on('click', function(e) {
        e.preventDefault();

        $('#sadran-malware-result')
            .text('Running malware scan...')
            .css({ 'color': '#888' });

        $.post(SADRAN_AJAX.ajaxurl, {
            action: 'sadran_run_malware',
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res) {
            if (res.success) {

                $('#sadran-malware-result')
                    .html('<strong>Malware scan completed.</strong>')
                    .css({ 'color': '#0a0' });

                console.log('Malware Scan Report:', res.data);

            } else {

                $('#sadran-malware-result')
                    .text('Error: ' + res.data)
                    .css({ 'color': '#c00' });
            }
        });
    });



    /* ------------------------------
       EXPORT INCIDENT LOG (JSON)
    ------------------------------ */
    $('#sadran-export-log').on('click', function(e) {
        e.preventDefault();

        let incidents = SADRAN_DATA.incidents || [];

        let blob = new Blob(
            [JSON.stringify(incidents, null, 2)], { type: 'application/json' }
        );

        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = 'sadran-incidents.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
    });


    /* ------------------------------
       OPTIONAL: Hardening apply button
    ------------------------------ */
    $('#sadran-apply-hardening').on('click', function(e) {
        e.preventDefault();

        let btn = $(this);
        btn.text('Applying...');

        $.post(SADRAN_AJAX.ajaxurl, {
            action: 'sadran_apply_hardening',
            _wpnonce: SADRAN_AJAX.nonce
        }, function(res) {
            if (res.success) {
                btn.text('Applied!');
            } else {
                btn.text('Error');
            }
        });
    });

});