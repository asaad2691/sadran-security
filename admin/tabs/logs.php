<?php
use SadranSecurity\Logging\LogsDB;

$limit = 50;
$offset = absint($_GET['offset'] ?? 0);

$logs   = LogsDB::instance()->fetch($limit, $offset);
$total  = LogsDB::instance()->count();
$next   = $offset + $limit;
$prev   = $offset - $limit;
?>

<div class="sadran-section">
    <h2>Security Logs</h2>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>Time</th>
                <th>IP</th>
                <th>Type</th>
                <th>Message</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
        <?php if (!empty($logs)): foreach ($logs as $log): ?>
            <tr>
                <td><?= esc_html(date('Y-m-d H:i:s', $log->time)); ?></td>
                <td><?= esc_html($log->ip); ?></td>
                <td><?= esc_html($log->type); ?></td>
                <td><?= esc_html($log->message); ?></td>
                <td><?= esc_html($log->severity); ?></td>
            </tr>
        <?php endforeach; else: ?>
            <tr><td colspan="5">No logs yet.</td></tr>
        <?php endif; ?>
        </tbody>
    </table>

    <div style="margin-top:20px;">
        <?php if ($prev >= 0): ?>
            <a class="button" href="?page=sadran-security&tab=logs&offset=<?= $prev ?>">Previous</a>
        <?php endif; ?>
        <?php if ($next < $total): ?>
            <a class="button" href="?page=sadran-security&tab=logs&offset=<?= $next ?>">Next</a>
        <?php endif; ?>
    </div>
</div>
