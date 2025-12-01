<?php
use SadranSecurity\Logging\LogsDB;

if (!defined('ABSPATH')) exit;

$limit  = 50;
$offset = absint($_GET['offset'] ?? 0);

$db     = LogsDB::instance();
$logs   = $db->fetch($limit, $offset);
$total  = $db->count();

$next   = $offset + $limit;
$prev   = max(0, $offset - $limit);
?>

<div class="sadran-section">
    <h2>Security Logs</h2>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th width="60">ID</th>
                <th width="160">Time</th>
                <th width="120">IP</th>
                <th width="140">Type</th>
                <th>Message</th>
                <th width="80">Severity</th>
                <th width="120">Details</th>
            </tr>
        </thead>

        <tbody>
        <?php if (!empty($logs)): foreach ($logs as $log): ?>
            <?php
                // Normalize time
                $ts = $log->time ?? ($log->created_at ?? null);
                if (is_numeric($ts)) {
                    $ts = date('Y-m-d H:i:s', intval($ts));
                }
            ?>
            <tr>
                <td><?= esc_html($log->id); ?></td>
                <td><?= esc_html($ts); ?></td>
                <td><?= esc_html($log->ip); ?></td>
                <td><?= esc_html($log->type); ?></td>
                <td><?= esc_html($log->message); ?></td>
                <td><?= esc_html($log->severity); ?></td>
                <td>
                    <?php
                        $meta_raw = $log->meta ?: $log->extra_json;
                        $meta_json = '';
                        if (!empty($meta_raw)) {
                            // Ensure valid JSON (fix malformed, fix arrays)
                            $decoded = json_decode($meta_raw, true);
                            
                            if (json_last_error() === JSON_ERROR_NONE) {
                                // Re-encode clean JSON
                                $meta_json = esc_attr(json_encode($decoded, JSON_PRETTY_PRINT));
                            } else {
                                // Try to convert array/object → JSON
                                if (is_array($meta_raw) || is_object($meta_raw)) {
                                    $meta_json = esc_attr(json_encode($meta_raw, JSON_PRETTY_PRINT));
                                } else {
                                    $meta_json = esc_attr($meta_raw);
                                }
                            }
                        }
                        
                        if (!empty($meta_raw)):
                    ?>
                        <button class="button view-json" data-json="<?= $meta_json; ?>">
                            View JSON
                        </button>
                    <?php else: ?>
                        <em>No meta</em>
                    <?php endif; ?>
                </td>
            </tr>
        <?php endforeach; else: ?>
            <tr><td colspan="7">No logs yet.</td></tr>
        <?php endif; ?>
        </tbody>
    </table>

    <!-- Pagination -->
    <div style="margin-top:20px;">
        <?php if ($prev >= 0 && $offset > 0): ?>
            <a class="button" href="?page=sadran-security&tab=logs&offset=<?= $prev ?>">Previous</a>
        <?php endif; ?>

        <?php if ($next < $total): ?>
            <a class="button" href="?page=sadran-security&tab=logs&offset=<?= $next ?>">Next</a>
        <?php endif; ?>
    </div>
</div>

<!-- JSON Modal -->
<div id="sadran-json-modal" style="display:none;">
    <div class="sadran-json-modal-content">
        <span class="close-json">&times;</span>
        <h3>Log Meta Data</h3>
        <pre id="json-output"></pre>
        <button class="button" id="copy-json">Copy JSON</button>
    </div>
</div>

<style>
#sadran-json-modal {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(0,0,0,0.7);
    z-index: 99999;
}
.sadran-json-modal-content {
    background: #1e1e1e;
    color: #fff;
    padding: 20px;
    width: 600px;
    margin: 100px auto;
    border-radius: 8px;
}
.close-json {
    float:right;
    cursor:pointer;
    font-size:24px;
}
</style>
<script>
jQuery(function($) {

    function decodeHtmlEntities(str) {
        return $('<textarea/>').html(str).text();
    }

    $(".view-json").on("click", function() {
        let raw = $(this).attr("data-json");
        raw = decodeHtmlEntities(raw);

        try {
            let parsed = JSON.stringify(JSON.parse(raw), null, 2);
            $("#json-output").text(parsed);
        } catch (e) {
            $("#json-output").text(raw);
        }

        $("#sadran-json-modal").fadeIn(150);
    });

    $(".close-json").on("click", function() {
        $("#sadran-json-modal").fadeOut(100);
    });

    $("#copy-json").on("click", function() {
        navigator.clipboard.writeText($("#json-output").text());
        alert("Copied!");
    });

});
</script>

