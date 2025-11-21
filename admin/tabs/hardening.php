<?php

use SadranSecurity\Hardening\UploadsProtector;
use SadranSecurity\Hardening\LoginHardener;

if (!defined('ABSPATH')) exit;

// helper for badges
function sadran_badge($enabled) {
    return $enabled
        ? '<span class="sadran-badge sadran-badge-green">ENABLED</span>'
        : '<span class="sadran-badge sadran-badge-red">DISABLED</span>';
}

// Detect each feature
$uploads_protected   = UploadsProtector::instance()->is_protection_active();
$login_hardening     = LoginHardener::instance()->is_rate_limit_active();
$xmlrpc_disabled     = apply_filters('xmlrpc_enabled', true) === false;
$file_edit_disabled  = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
$rest_restricted     = get_option('sadran_restrict_rest', false);
$bad_agents_blocked  = get_option('sadran_block_bad_agents', false);

?>

<div class="sadran-section">
    <h2>Hardening Overview</h2>

    <div class="sadran-card">
        <h3>Uploads Protection <?= sadran_badge($uploads_protected); ?></h3>
        <p>Protects /uploads from executing malicious PHP files.</p>
    </div>

    <div class="sadran-card">
        <h3>Login Hardening <?= sadran_badge($login_hardening); ?></h3>
        <p>Brute-force protection + login rate limiting.</p>
    </div>

    <div class="sadran-card">
        <h3>Disable File Editor <?= sadran_badge($file_edit_disabled); ?></h3>
        <p>Prevents attackers from modifying theme/plugin files via wp-admin.</p>
    </div>

    <div class="sadran-card">
        <h3>Disable XML-RPC <?= sadran_badge($xmlrpc_disabled); ?></h3>
        <p>Stops XML-RPC authentication attacks.</p>
    </div>

    <div class="sadran-card">
        <h3>Restrict REST API <?= sadran_badge($rest_restricted); ?></h3>
        <p>Blocks unauthenticated users from harvesting site info.</p>
    </div>

    <div class="sadran-card">
        <h3>Block Bad User Agents <?= sadran_badge($bad_agents_blocked); ?></h3>
        <p>Stops scanners, scrapers, and known malicious bots.</p>
    </div>
</div>

<style>
.sadran-badge {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: bold;
    color: #fff;
}
.sadran-badge-green { background:#28a745; }
.sadran-badge-red   { background:#dc3545; }

.sadran-card h3 {
    margin-top:0;
}
</style>
