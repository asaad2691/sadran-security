<div class="sadran-section">
    <h2>Settings</h2>

    <form method="post" action="options.php">
        <?php settings_fields('sadran_settings'); ?>
        <?php do_settings_sections('sadran_settings'); ?>

        <table class="form-table">
            <tr>
                <th>Email Notifications</th>
                <td>
                    <input type="checkbox" name="sadran_email" value="1"
                        <?= checked(get_option('sadran_email'),1,false) ?> />
                    Enable
                </td>
            </tr>
        </table>

        <button type="submit" class="button button-primary">Save Settings</button>
    </form>
</div>
