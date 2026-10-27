<?php
/** Optional local acceptance test against prepare_site_patch.py output. */
if (getenv('WORDPRESS_DB_PASSWORD') !== 'fixture-only' || getenv('WORDPRESS_DB_HOST') !== 'db') {
    throw new RuntimeException('Disposable fixture required');
}
$scenario = $argv[1] ?? '';
$cases = array('valid', 'stale_terms', 'missing_terms', 'invalid_nonce', 'honeypot', 'bad_target', 'missing_acceptance');
if ('' === $scenario) {
    foreach ($cases as $case) {
        passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' ' . escapeshellarg($case), $status);
        if ($status) { exit($status); }
    }
    echo "Prepared site handler checks passed.\n";
    exit;
}
if (!in_array($scenario, $cases, true)) { throw new RuntimeException('Unknown fixture'); }
$config_file = tempnam('/tmp', 'ct-site-fixture-');
file_put_contents($config_file, '<?php return ' . var_export(array(
    'enabled' => true,
    'worker_hmac_secret' => str_repeat('fixture-', 8),
    'expected_checker_revision' => str_repeat('a', 40),
    'authorization_end_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 86400 * 30),
    'global_daily_limit' => 1000,
    'target_daily_limit' => 10,
), true) . ';');
define('CT_SCAN_PRIVATE_CONFIG', $config_file);
register_shutdown_function(static function () use ($config_file) { unlink($config_file); });
$_SERVER['HTTP_HOST'] = 'wordpress';
$_SERVER['REMOTE_ADDR'] = '192.0.2.2';
$_SERVER['HTTP_USER_AGENT'] = 'Local fixture';
require '/var/www/html/wp-load.php';
require '/work/.work/site/theme/spintech-child/functions.php';
require '/work/.work/site/mu-plugins/ct-promo-terms.php';
register_post_type('ct_promo_request', array('public' => false));
if (!ct_promo()) { throw new RuntimeException('The prepared promotion has expired; refresh fixture terms first'); }

function site_assert($condition, $message) {
    if (!$condition) { throw new RuntimeException($message); }
}
class FixtureRedirect extends RuntimeException {}
add_filter('wp_redirect', static function ($location) { throw new FixtureRedirect($location); });
$mail = array();
add_filter('pre_wp_mail', static function ($return, $atts) use (&$mail) {
    $mail[] = $atts;
    return true;
}, 10, 2);
function ct_promo_send_notification($id, $to, $subject, $body, $headers) {
    $GLOBALS['ct_promo_mail_in_progress'] = true;
    try { return wp_mail($to, $subject, $body, $headers); }
    finally { $GLOBALS['ct_promo_mail_in_progress'] = false; }
}
$terms = array('ID' => 658, 'post_type' => 'page', 'post_status' => 'publish',
    'post_title' => 'Fixture scan terms', 'post_content' => file_get_contents('/work/.work/site/content/php2shell-scan-terms.html'));
if (get_post(658)) { wp_update_post(wp_slash($terms)); }
else { unset($terms['ID']); $terms['import_id'] = 658; wp_insert_post(wp_slash($terms)); }
$post_data = array(
    'ct_promo_nonce' => wp_create_nonce('ct_promo_request'),
    'ct_name' => "O'Reilly Fixture", 'ct_email' => 'fixture@example.com',
    'ct_website' => 'https://site-fixture.example.com/', 'ct_phone' => '',
    'ct_ref' => 'lily', 'ct_agree' => '1', 'ct_terms_version' => ct_promo_terms()['version'],
);
if ('stale_terms' === $scenario) { $post_data['ct_terms_version'] = 'old'; }
if ('missing_terms' === $scenario) { unset($post_data['ct_agree']); }
if ('invalid_nonce' === $scenario) { $post_data['ct_promo_nonce'] = 'invalid'; }
if ('honeypot' === $scenario) { $post_data['ct_hp'] = 'bot'; }
if ('bad_target' === $scenario) { $post_data['ct_website'] = "https://site-fixture.example.com/\n"; }
if ('missing_acceptance' === $scenario) {
    $block = static function ($check, $id, $key) { return '_ct_terms_contract' === $key ? false : $check; };
    add_filter('add_post_metadata', $block, 10, 3);
    add_filter('update_post_metadata', $block, 10, 3);
}
$_POST = wp_slash($post_data);
global $wpdb;
$before = (int)$wpdb->get_var("SELECT MAX(ID) FROM {$wpdb->posts}");
try { do_action('admin_post_nopriv_ct_promo_request'); throw new RuntimeException('Missing redirect'); }
catch (FixtureRedirect $redirect) { $location = $redirect->getMessage(); }
$ids = $wpdb->get_col($wpdb->prepare("SELECT ID FROM {$wpdb->posts} WHERE post_type='ct_promo_request' AND ID>%d", $before));
$expects_post = in_array($scenario, array('valid', 'missing_acceptance'), true);
site_assert(count($ids) === ($expects_post ? 1 : 0), $scenario . ': request persistence');
if ($expects_post) {
    $id = (int)$ids[0];
    $post = get_post($id);
    site_assert('private' === $post->post_status, 'Request must stay private');
    site_assert('lily' === get_post_meta($id, '_ct_ref', true), 'Referral lost');
    site_assert("O'Reilly Fixture" === get_post_meta($id, '_ct_scan_name', true), 'Contact damaged');
    $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . ct_scan_jobs_table() . ' WHERE request_id=%d', $id));
    if ('valid' === $scenario) {
        site_assert($row && 'awaiting_confirmation' === $row->status, 'Missing gated job');
        site_assert('1' === get_post_meta($id, '_ct_terms_saved', true), 'Acceptance marker missing');
        site_assert(hash('sha256', $terms['post_content']) === $row->terms_hash, 'Wrong terms hash');
        site_assert(count($mail) === 2, 'Confirmation and administrator notification required');
        site_assert(false !== strpos($mail[1]['message'], 'TERMS AS ACCEPTED'), 'Admin contract attachment missing');
        site_assert(false !== strpos($mail[1]['message'], 'Referred by: lily'), 'Admin referral missing');
    } else {
        site_assert(!$row, 'Incomplete acceptance queued');
        site_assert(count($mail) === 1, 'Admin notification must survive queue rejection');
    }
    $wpdb->delete(ct_scan_jobs_table(), array('request_id' => $id));
    wp_delete_post($id, true);
} else { site_assert(count($mail) === 0, 'Invalid request sent mail'); }
echo $scenario . ": passed\n";
