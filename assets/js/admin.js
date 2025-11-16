jQuery(function($) {

    $("#sadran-run-scan").on("click", function(e) {
        e.preventDefault();

        $("#sadran-scan-result").html("Running scan...");

        $.post(SADRAN_AJAX.ajaxurl, {
            action: "sadran_run_scan",
            _ajax_nonce: SADRAN_AJAX.nonce
        }, function(res) {
            if (res.success) {
                $("#sadran-scan-result").html("<strong>Scan complete.</strong>");
            } else {
                $("#sadran-scan-result").html("Error: " + res.data);
            }
        });
    });

});