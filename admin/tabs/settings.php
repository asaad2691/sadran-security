<?php
if (!current_user_can('manage_options')) wp_die();
if (isset($_POST['sadran_settings_save']) && check_admin_referer('sadran_settings')) {
    $opts = [
        'disable_file_edit' => isset($_POST['disable_file_edit']) ? 1 : 0,
        'disable_xmlrpc' => isset($_POST['disable_xmlrpc']) ? 1 : 0,
        'restrict_rest' => isset($_POST['restrict_rest']) ? 1 : 0,
        'block_bad_ua' => isset($_POST['block_bad_ua']) ? 1 : 0,
        'uploads_htaccess' => isset($_POST['uploads_htaccess']) ? 1 : 0,
        'ui_dark' => isset($_POST['ui_dark']) ? 1 : 0,
    ];
    foreach ($opts as $k => $v) update_option('sadran_hardening_' . $k, $v);
    update_option('sadran_ui_dark', $opts['ui_dark']);
    echo '<div class="updated"><p>Settings saved.</p></div>';
}
?>
<div class="sadran-section">
    <h2>Settings</h2>
    <form method="post">
        <?php wp_nonce_field('sadran_settings'); ?>
        <table class="form-table">
            <tr><th>Disable file editor</th>
                <td><input type="checkbox" name="disable_file_edit" value="1" <?= checked(get_option('sadran_hardening_disable_file_edit',0),1,false) ?>></td></tr>
            <tr><th>Disable XML-RPC</th>
                <td><input type="checkbox" name="disable_xmlrpc" value="1" <?= checked(get_option('sadran_hardening_disable_xmlrpc',0),1,false) ?>></td></tr>
            <tr><th>Restrict REST API</th>
                <td><input type="checkbox" name="restrict_rest" value="1" <?= checked(get_option('sadran_hardening_restrict_rest',0),1,false) ?>></td></tr>
            <tr><th>Block common bad user agents</th>
                <td><input type="checkbox" name="block_bad_ua" value="1" <?= checked(get_option('sadran_hardening_block_bad_ua',0),1,false) ?>></td></tr>
            <tr><th>Deploy uploads .htaccess</th>
                <td><input type="checkbox" name="uploads_htaccess" value="1" <?= checked(get_option('sadran_hardening_uploads_htaccess',0),1,false) ?>></td></tr>
            <tr><th>Admin UI Dark Mode</th>
                <td><input type="checkbox" name="ui_dark" value="1" <?= checked(get_option('sadran_ui_dark',0),1,false) ?>></td></tr>
        </table>
        <p><button class="button button-primary" name="sadran_settings_save">Save</button></p>
    </form>
</div>
