<?php $inc = (array)get_option('sadran_incidents',[]); ?>

<div class="sadran-section">
    <h2>Incident Logs</h2>

    <?php if (!$inc) : ?>
        <p>No incidents logged.</p>
    <?php else : ?>
        <ul class="sadran-log-list">
            <?php foreach (array_reverse($inc) as $i): ?>
                <li>
                    <strong><?= date('Y-m-d H:i:s',$i['time']) ?></strong> — <?= esc_html($i['type']) ?>
                    <pre><?= esc_html(print_r($i['detail'],true)) ?></pre>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>
