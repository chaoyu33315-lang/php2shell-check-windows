<?php
/**
 * Exact-target control: DNS TXT / HTTPS file challenge limits, manual authority review, blocked
 * outcome, and the report/admission gates. Disposable fixture only. Re-runs itself with the strict
 * terms policy (which requires target control).
 */
if ( 'strict' !== getenv( 'CT_TEST_POLICY' ) ) {
	$env  = array_merge( getenv(), array( 'CT_TEST_POLICY' => 'strict' ) );
	$proc = proc_open( array( PHP_BINARY, __FILE__ ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, $env );
	echo stream_get_contents( $pipes[1] ), stream_get_contents( $pipes[2] );
	exit( proc_close( $proc ) );
}
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
$mail = array();
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail ) {
	$mail[] = $atts;
	return true;
}, 10, 2 );

/** A confirmed job waiting for target control. Returns its ids and the challenge token the customer saw. */
function ct_test_control_job( $host ) {
	global $mail, $request_ids, $wpdb;
	// Scenarios are sequential: end any earlier job still holding a requested or in-progress check.
	$wpdb->query( "UPDATE " . ct_scan_jobs_table() . " SET status = 'cancelled', error_code = 'test_cleanup', control_state = 'none' WHERE status = 'awaiting_control' AND control_state IN ('requested','checking')" );
	list( $request_id, $fields ) = ct_test_request( $host );
	$request_ids[] = $request_id;
	ct_test_bind( $request_id, $fields ); // strict policy: bound evidence and control are both required
	$before = count( $mail );
	$event  = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_array( $event ), 'Control fixture job was not created.' );
	ct_test_assert( 1 === (int) ct_scan_row( $event['job_id'] )->control_required, 'The job did not freeze control_required.' );
	preg_match( '/token=([a-f0-9]{64})/', $mail[ $before ]['message'], $m );
	list( $message, $status, $markup ) = ct_scan_confirm_job( $event['job_id'], $m[1] );
	ct_test_assert( 200 === $status && 1 === preg_match( '/ct-scan-verify=([a-f0-9]{64})/', $markup, $t ) && 1 === preg_match( '/name="ctl" value="([a-f0-9]{64})"/', $markup, $p ), 'Confirmation did not present a challenge and a page capability.' );
	return array( 'request_id' => $request_id, 'fields' => $fields, 'job_id' => (int) $event['job_id'], 'token' => $t[1], 'page' => $p[1], 'markup' => $markup );
}

function ct_test_control_claim() {
	$response = ct_test_rest_call( 'ct_scan_control_claim', '/ct-scan/v1/control/claim', array() );
	return $response->get_data()['task'] ?? null;
}

function ct_test_control_admit( $task, $kind = 'control', $override = array() ) {
	return ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', array_merge( array( 'id' => $task['id'], 'lease' => $task['lease'], 'scope_hash' => $task['scope_hash'], 'kind' => $kind ), $override ) );
}

function ct_test_control_result( $task, $outcome, $observed = array(), $override = array() ) {
	return ct_test_rest_call( 'ct_scan_control_result', '/ct-scan/v1/control/result', array_merge( array( 'id' => $task['id'], 'lease' => $task['lease'], 'scope_hash' => $task['scope_hash'], 'method' => $task['method'], 'outcome' => $outcome, 'observed' => $observed ), $override ) );
}

/** Make the previous check old enough that the one-minute interval allows the next. */
function ct_test_age_control( $job_id ) {
	global $wpdb;
	$wpdb->query( $wpdb->prepare( 'UPDATE ' . ct_scan_jobs_table() . ' SET control_last_attempt_ms = control_last_attempt_ms - 61000 WHERE job_id = %d', $job_id ) );
}

/** One full check: request, claim, admit, result. Returns the result response. */
function ct_test_run_check( $job, $method, $observed, $outcome = 'observed' ) {
	global $wpdb;
	$r = ct_scan_request_control_check( $job['job_id'], $job['page'], $method );
	ct_test_assert( 'scheduled' === $r, 'A check could not be scheduled: ' . ( is_wp_error( $r ) ? $r->get_error_code() : $r ) );
	$task = ct_test_control_claim();
	ct_test_assert( $task && (int) $task['id'] === $job['job_id'], 'The scheduled check was not claimed.' );
	$grant = ct_test_control_admit( $task );
	ct_test_assert( 200 === $grant->get_status(), 'The check was not admitted: ' . wp_json_encode( $grant->get_data() ) );
	return ct_test_control_result( $task, $outcome, $observed );
}

// ---- Confirmation no longer queues: mailbox control is not target control -----------------------------
$a = ct_test_control_job( 'control-a.example.net' );
$row = ct_scan_row( $a['job_id'] );
ct_test_assert( 'awaiting_control' === $row->status && 'pending' === $row->control_state && ! empty( $row->confirmed_at ) && hash( 'sha256', $a['token'] ) === $row->control_token_hash && hash( 'sha256', $a['page'] ) === $row->control_page_hash, 'Confirmation did not leave the job awaiting target control with hashed secrets.' );
// Two independent secrets: the published challenge value is not the page capability.
ct_test_assert( $a['token'] !== $a['page'] && $a['token'] === ct_scan_control_challenge( $row, $a['page'] ) && false === strpos( wp_json_encode( $row ), $a['page'] ), 'The challenge and the page capability are not independent, or the capability is stored.' );
ct_test_assert( false === strpos( $a['markup'], 'ct-scan-verify=' . $a['page'] ), 'The page capability is shown as the challenge.' );
ct_test_assert( false === strpos( wp_json_encode( $row ), $a['token'] ), 'The raw challenge token is stored.' );
ct_test_assert( false !== strpos( $a['markup'], '_ct-scan-challenge.control-a.example.net' ) && false !== strpos( $a['markup'], 'https://control-a.example.net/.well-known/ct-scan-challenge.txt' ), 'The instructions do not name the exact hostname and fixed paths.' );
ct_test_assert( 'awaiting_control' === get_post_meta( $a['request_id'], '_ct_scan_status', true ), 'The request status did not record the wait.' );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'], 'A job awaiting target control was claimable for scanning.' );
$fake_running = array( 'job' => array( 'id' => $a['job_id'], 'lease' => str_repeat( '1', 64 ), 'scope_hash' => $row->scope_hash ) );
ct_test_assert( 410 === ct_test_admit( $fake_running, 'http' )->get_status(), 'A job awaiting target control was admitted for scanning.' );
ct_test_assert( 410 === ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $a['job_id'], 'lease' => str_repeat( '1', 64 ), 'scope_hash' => $row->scope_hash ) )->get_status(), 'A job awaiting target control could be started.' );

// A legacy job (control not required) is unchanged: confirmation queues it.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'control-legacy.example.net' );
$request_ids[] = $legacy_id;
ct_test_bind( $legacy_id, $legacy_fields );
$before = count( $mail );
$legacy = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
$wpdb->update( $jobs, array( 'control_required' => 0 ), array( 'job_id' => $legacy['job_id'] ) );
preg_match( '/token=([a-f0-9]{64})/', $mail[ $before ]['message'], $m );
list( , $legacy_status ) = ct_scan_confirm_job( $legacy['job_id'], $m[1] );
ct_test_assert( 200 === $legacy_status && 'queued' === ct_scan_row( $legacy['job_id'] )->status, 'A job that does not require target control was not queued by confirmation.' );
$wpdb->update( $jobs, array( 'status' => 'cancelled', 'error_code' => 'test_cleanup' ), array( 'job_id' => $legacy['job_id'] ) );

// ---- Scheduling a check: customer-driven, bound to the secret, limited ------------------------------
ct_test_assert( is_wp_error( ct_scan_request_control_check( $a['job_id'], str_repeat( 'a', 64 ), 'dns_txt' ) ), 'A wrong page capability scheduled a check.' );
// Anyone can read the published challenge; it must not let them use up the customer's checks.
ct_test_assert( 'control_link_invalid' === ct_scan_request_control_check( $a['job_id'], $a['token'], 'dns_txt' )->get_error_code() && 'pending' === ct_scan_row( $a['job_id'] )->control_state && 0 === (int) ct_scan_row( $a['job_id'] )->control_attempts, 'The published challenge value scheduled a check.' );
ct_test_assert( 'control_method_invalid' === ct_scan_request_control_check( $a['job_id'], $a['page'], 'http' )->get_error_code(), 'An unsupported method was accepted.' );
ct_test_assert( 'pending' === ct_scan_row( $a['job_id'] )->control_state, 'A rejected request changed the state.' );
ct_test_assert( 'scheduled' === ct_scan_request_control_check( $a['job_id'], $a['page'], 'dns_txt' ), 'A valid check was not scheduled.' );
ct_test_assert( 'control_check_in_progress' === ct_scan_request_control_check( $a['job_id'], $a['page'], 'https_file' )->get_error_code(), 'A second check was scheduled while one is outstanding.' );
ct_test_assert( 0 === (int) ct_scan_row( $a['job_id'] )->control_attempts, 'Scheduling consumed an attempt (only an admission may).' );

// ---- Claim and admission -----------------------------------------------------------------------------
$task = ct_test_control_claim();
ct_test_assert( $task && 'dns_txt' === $task['method'] && (int) $task['id'] === $a['job_id'] && hash( 'sha256', 'https://control-a.example.net/' ) === $task['scope_hash'], 'The control task does not name the exact target and chosen method.' );
ct_test_assert( null === ct_test_control_claim(), 'A checking job was claimed twice.' );
ct_test_assert( 410 === ct_test_control_admit( $task, 'control', array( 'lease' => str_repeat( 'c', 64 ) ) )->get_status(), 'A control admission with a foreign lease was granted.' );
ct_test_assert( 410 === ct_test_control_admit( $task, 'control', array( 'scope_hash' => str_repeat( 'd', 64 ) ) )->get_status(), 'A control admission with a foreign scope was granted.' );
ct_test_assert( 200 === ct_test_control_admit( $task, 'control_probe' )->get_status() && 0 === (int) ct_scan_row( $a['job_id'] )->control_attempts, 'A probe consumed an attempt or failed.' );
// Without an admission the worker cannot get a result recorded.
$noadm = ct_test_control_result( $task, 'observed', array( 'ct-scan-verify=' . $a['token'] ) );
ct_test_assert( 409 === $noadm->get_status() && 'awaiting_control' === ct_scan_row( $a['job_id'] )->status, 'A result was accepted for a check that was never admitted.' );
$grant = ct_test_control_admit( $task );
$gd = $grant->get_data();
ct_test_assert( 200 === $grant->get_status() && 1 === $gd['sequence'] && 1000 === $gd['valid_ms'] && 10000 === $gd['timeout_ms'] && 2 === $gd['http_remaining'] && 1 === (int) ct_scan_row( $a['job_id'] )->control_attempts, 'The first control admission was not granted with the disclosed bounds.' );
$again = ct_test_control_admit( $task );
ct_test_assert( 409 === $again->get_status() && 'already_admitted' === $again->get_data()['reason'] && 1 === (int) ct_scan_row( $a['job_id'] )->control_attempts, 'A second control request under the same lease was admitted.' );
// The lease (two minutes) outlives the one-minute interval: once the interval has passed, the same
// lease is still refused and the customer's remaining checks are untouched.
$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET control_last_attempt_ms = control_last_attempt_ms - 61000, control_leased_ms = control_leased_ms - 61000 WHERE job_id = %d", $a['job_id'] ) );
$late = ct_test_control_admit( $task );
$row  = ct_scan_row( $a['job_id'] );
ct_test_assert( 409 === $late->get_status() && 'already_admitted' === $late->get_data()['reason'] && 1 === (int) $row->control_attempts && 'checking' === $row->control_state, 'A lease was admitted twice once the one-minute interval had passed.' );
$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET control_last_attempt_ms = control_last_attempt_ms + 61000, control_leased_ms = control_leased_ms + 61000 WHERE job_id = %d", $a['job_id'] ) );
// A forged / wrong-method / malformed result is rejected and keeps the check open.
foreach ( array(
	array( 'observed', array( 'ct-scan-verify=' . $a['token'] ), array( 'method' => 'https_file' ), 410 ),
	array( 'observed', array( 'ct-scan-verify=' . $a['token'] ), array( 'lease' => str_repeat( 'e', 64 ) ), 410 ),
	array( 'observed', 'ct-scan-verify=' . $a['token'], array(), 400 ),
	array( 'observed', array_fill( 0, 9, 'x' ), array(), 400 ),
	array( 'observed', array( str_repeat( 'x', 4097 ) ), array(), 400 ),
	array( 'observed', array( str_repeat( 'x', 2500 ), str_repeat( 'y', 2500 ) ), array(), 400 ),
	array( 'observed', array( 5 ), array(), 400 ),
	array( 'not_found', array( 'ct-scan-verify=' . $a['token'] ), array(), 400 ),
	array( 'verified', array(), array(), 400 ),
) as $i => $case ) {
	$bad = ct_test_control_result( $task, $case[0], $case[1], $case[2] );
	ct_test_assert( $case[3] === $bad->get_status() && 'awaiting_control' === ct_scan_row( $a['job_id'] )->status, "Malformed result case $i was accepted ({$bad->get_status()})." );
}
// A value that is not the challenge does not verify, however close.
$token = $a['token'];
foreach ( array(
	'ct-scan-verify=' . strtoupper( $token ), 'ct-scan-verify=' . substr( $token, 0, 63 ), 'ct-scan-verify=' . $token . 'x', ' ct-scan-verify=' . $token,
	'ct-scan-verify= ' . $token, $token, 'ct-scan-verify=' . str_repeat( 'a', 64 ), 'ct-scan-verify=' . "\0" . $token,
) as $near ) {
	ct_test_assert( ! ct_scan_control_value_matches( 'dns_txt', $near, hash( 'sha256', $token ) ), 'A near-miss DNS value verified: ' . bin2hex( substr( $near, 0, 20 ) ) );
}
ct_test_assert( ct_scan_control_value_matches( 'dns_txt', 'ct-scan-verify=' . $token, hash( 'sha256', $token ) ), 'The exact DNS value did not verify.' );
foreach ( array( $token, $token . "\n", $token . "\r\n", " \t" . $token, "\xEF\xBB\xBF" . $token . "\n" ) as $ok ) {
	ct_test_assert( ct_scan_control_value_matches( 'https_file', $ok, hash( 'sha256', $token ) ), 'The file challenge did not verify with harmless whitespace.' );
}
foreach ( array( 'prefix ' . $token, $token . ' suffix', strtoupper( $token ), 'ct-scan-verify=' . $token, '', "\xEF\xBB\xBF\xEF\xBB\xBF" . $token, $token . "\xEF\xBB\xBF" ) as $near ) {
	ct_test_assert( ! ct_scan_control_value_matches( 'https_file', $near, hash( 'sha256', $token ) ), 'A near-miss file value verified.' );
}
// First honest failure: the DNS record is not there yet. The check is used, the job keeps waiting.
$fail1 = ct_test_control_result( $task, 'not_found' );
$row = ct_scan_row( $a['job_id'] );
ct_test_assert( 200 === $fail1->get_status() && false === $fail1->get_data()['verified'] && 'awaiting_control' === $row->status && 'pending' === $row->control_state && 1 === (int) $row->control_attempts && empty( $row->control_lease_hash ), 'A failed check did not return the job to waiting with the attempt spent.' );
ct_test_assert( 'control_too_soon' === ct_scan_request_control_check( $a['job_id'], $a['page'], 'dns_txt' )->get_error_code(), 'A check was scheduled inside the one-minute interval.' );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'], 'A failed check made the job claimable.' );
ct_test_assert( 409 === ct_test_control_result( $task, 'observed', array( 'ct-scan-verify=' . $a['token'] ) )->get_status() || 410 === ct_test_control_result( $task, 'observed', array( 'ct-scan-verify=' . $a['token'] ) )->get_status(), 'A spent task accepted another result.' );

// Second check by file, with the right value: verified, evidence stores only a hash, job becomes claimable.
ct_test_age_control( $a['job_id'] );
$ok = ct_test_run_check( $a, 'https_file', array( $a['token'] . "\n" ) );
$row = ct_scan_row( $a['job_id'] );
$evidence = json_decode( $row->control_evidence, true );
ct_test_assert( 200 === $ok->get_status() && true === $ok->get_data()['verified'] && 'queued' === $row->status && 'https_file' === $row->control_method && ! empty( $row->control_verified_at ) && null === $row->control_token_hash && 2 === (int) $row->control_attempts, 'A correct file challenge did not verify the target.' );
ct_test_assert( 'https_file' === $evidence['method'] && 2 === $evidence['attempt'] && $evidence['target'] === $a['fields']['target'] && hash( 'sha256', $a['token'] . "\n" ) === $evidence['observed_sha256'] && false === strpos( $row->control_evidence, $a['token'] ), 'The verification evidence is wrong or contains the secret.' );
$claimed = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'];
ct_test_assert( is_array( $claimed ) && (int) $claimed['id'] === $a['job_id'], 'A verified job was not claimable.' );
$started = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'] ) );
ct_test_assert( 200 === $started->get_status(), 'A verified job could not start.' );
ct_test_assert( 200 === ct_test_admit( array( 'job' => $claimed ) )->get_status(), 'A verified, running job was not admitted.' );
// Replaying the control token after success does nothing.
ct_test_assert( is_wp_error( ct_scan_request_control_check( $a['job_id'], $a['page'], 'dns_txt' ) ), 'A spent challenge scheduled another check.' );
ct_test_end_job( $a['job_id'] );

// ---- Three failures end in `blocked`, never in a scan ------------------------------------------------
$b = ct_test_control_job( 'control-b.example.net' );
for ( $i = 1; $i <= 3; $i++ ) {
	if ( $i > 1 ) {
		ct_test_age_control( $b['job_id'] );
	}
	$res = ct_test_run_check( $b, 1 === $i % 2 ? 'dns_txt' : 'https_file', array( 'unrelated-text' ) );
	ct_test_assert( 200 === $res->get_status() && false === $res->get_data()['verified'], "Failed check $i was reported verified." );
}
$row = ct_scan_row( $b['job_id'] );
ct_test_assert( 'blocked' === $row->status && 'target_control_failed' === $row->error_code && 3 === (int) $row->control_attempts && null === $row->control_token_hash && ! empty( $row->finished_at ), 'Three failed checks did not block the job.' );
ct_test_assert( 'blocked' === get_post_meta( $b['request_id'], '_ct_scan_status', true ), 'The request did not record the blocked state.' );
ct_test_assert( is_wp_error( ct_scan_request_control_check( $b['job_id'], $b['page'], 'dns_txt' ) ), 'A blocked job accepted another check.' );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'], 'A blocked job was claimed for scanning.' );
ct_test_assert( 410 === ct_test_admit( array( 'job' => array( 'id' => $b['job_id'], 'lease' => str_repeat( '2', 64 ), 'scope_hash' => $row->scope_hash ) ), 'http' )->get_status(), 'A blocked job was admitted for scanning.' );
// Even with operator notes, a blocked job gets no detailed report.
$wpdb->update( $jobs, array( 'manual_remainder_status' => 'complete', 'manual_remainder_notes' => 'Operator notes.' ), array( 'job_id' => $b['job_id'] ) );
$mail_before_report = count( $mail );
$report = ct_scan_admin_send_report( $b['job_id'] );
ct_test_assert( is_wp_error( $report ) && 'report_target_unverified' === $report->get_error_code(), 'A detailed report path opened for a target whose control was never shown.' );
ct_test_assert( count( $mail ) === $mail_before_report, 'Mail was sent for a blocked job.' );

// ---- Lapsed lease, customer stop, expiry --------------------------------------------------------------
$c = ct_test_control_job( 'control-c.example.net' );
ct_scan_request_control_check( $c['job_id'], $c['page'], 'dns_txt' );
$task_c = ct_test_control_claim();
ct_test_assert( 200 === ct_test_control_admit( $task_c )->get_status(), 'Fixture admission failed.' );
$wpdb->update( $jobs, array( 'control_lease_until' => gmdate( 'Y-m-d H:i:s', time() - 5 ) ), array( 'job_id' => $c['job_id'] ) );
ct_test_assert( 410 === ct_test_control_result( $task_c, 'observed', array( 'ct-scan-verify=' . $c['token'] ) )->get_status(), 'A result after the lease lapsed was accepted.' );
$row = ct_scan_row( $c['job_id'] );
ct_test_assert( 'awaiting_control' === $row->status && 'pending' === $row->control_state && 1 === (int) $row->control_attempts, 'A lapsed lease refunded the attempt or stranded the job.' );
// Stop while a check is scheduled: nothing more is admitted or recorded.
ct_test_age_control( $c['job_id'] );
ct_scan_request_control_check( $c['job_id'], $c['page'], 'dns_txt' );
$task_c2 = ct_test_control_claim();
$stop_token = bin2hex( random_bytes( 32 ) );
$wpdb->update( $jobs, array( 'stop_token_hash' => hash( 'sha256', $stop_token ) ), array( 'job_id' => $c['job_id'] ) );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $c['job_id'], $stop_token ), 'Customer stop failed during target control.' );
$after = ct_scan_row( $c['job_id'] );
ct_test_assert( 'cancelled' === $after->status && null === $after->control_token_hash && 'none' === $after->control_state, 'Stop did not clear the control state.' );
ct_test_age_control( $c['job_id'] );
ct_test_assert( 410 === ct_test_control_admit( $task_c2 )->get_status() && 410 === ct_test_control_admit( $task_c2, 'control_probe' )->get_status(), 'A control check was admitted after Stop.' );
ct_test_assert( 410 === ct_test_control_result( $task_c2, 'observed', array( 'ct-scan-verify=' . $c['token'] ) )->get_status(), 'A result was accepted after Stop.' );

$d = ct_test_control_job( 'control-d.example.net' );
ct_scan_request_control_check( $d['job_id'], $d['page'], 'https_file' );
$task_d = ct_test_control_claim();
$wpdb->update( $jobs, array( 'authorization_expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ), array( 'job_id' => $d['job_id'] ) );
$exp = ct_test_control_admit( $task_d );
ct_test_assert( 410 === $exp->get_status() && 'job_expired' === $exp->get_data()['reason'] && 'expired' === ct_scan_row( $d['job_id'] )->status && 0 === (int) ct_scan_row( $d['job_id'] )->control_attempts, 'A control check was admitted after authorization expiry.' );

// Fault: a thrown exception or a lost compare-and-set refuses.
$e = ct_test_control_job( 'control-e.example.net' );
ct_scan_request_control_check( $e['job_id'], $e['page'], 'dns_txt' );
$task_e = ct_test_control_claim();
$racer = static function ( $sql ) use ( &$raced, $jobs, $e ) {
	global $wpdb;
	if ( ! $raced && 0 === strpos( ltrim( $sql ), "UPDATE `{$jobs}` SET `control_attempts`" ) ) {
		$raced = true;
		$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET control_attempts = 2 WHERE job_id = %d", $e['job_id'] ) );
	}
	return $sql;
};
$raced = false;
add_filter( 'query', $racer );
$lost = ct_test_control_admit( $task_e );
remove_filter( 'query', $racer );
ct_test_assert( $raced && 503 === $lost->get_status() && 'admission_write_failed' === $lost->get_data()['reason'] && 2 === (int) ct_scan_row( $e['job_id'] )->control_attempts, 'A lost control reservation race was granted or overwritten.' );
$wpdb->update( $jobs, array( 'control_attempts' => 0, 'control_last_attempt_ms' => null ), array( 'job_id' => $e['job_id'] ) );
$thrower = static function ( $sql ) use ( $jobs ) {
	if ( 0 === strpos( ltrim( $sql ), "UPDATE `{$jobs}` SET `control_attempts`" ) ) {
		throw new RuntimeException( 'injected database fault' );
	}
	return $sql;
};
add_filter( 'query', $thrower );
$faulted = ct_test_control_admit( $task_e );
remove_filter( 'query', $thrower );
ct_test_assert( 503 === $faulted->get_status() && 0 === (int) ct_scan_row( $e['job_id'] )->control_attempts, 'A database fault during control admission did not fail closed.' );
ct_test_assert( ct_scan_lock_acquire(), 'The queue lock leaked after a faulted control admission.' );
ct_scan_lock_release();

// ---- Cases that defend the central invariants directly (not only through the happy path) ----------------------
// A control-required job forced into `queued` without verified control is never claimed, and is cancelled.
$g = ct_test_control_job( 'control-g.example.net' );
$wpdb->update( $jobs, array( 'status' => 'queued', 'control_state' => 'none' ), array( 'job_id' => $g['job_id'] ) );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'] && 'cancelled' === ct_scan_row( $g['job_id'] )->status, 'A control-required job without verified control was claimable.' );
// ...and a leased/running one is refused at start and admission.
$h = ct_test_control_job( 'control-h.example.net' );
$wpdb->update( $jobs, array( 'status' => 'running', 'attempts' => 1, 'lease_hash' => hash( 'sha256', str_repeat( '3', 64 ) ), 'lease_until' => gmdate( 'Y-m-d H:i:s', time() + 200 ) ), array( 'job_id' => $h['job_id'] ) );
$bad_admit = ct_test_admit( array( 'job' => array( 'id' => $h['job_id'], 'lease' => str_repeat( '3', 64 ), 'scope_hash' => ct_scan_row( $h['job_id'] )->scope_hash ) ) );
ct_test_assert( 410 === $bad_admit->get_status() && 'authorization_revoked_or_expired' === $bad_admit->get_data()['reason'], 'A running, unverified, control-required job was admitted.' );
// The fourth admission is refused even with a valid lease and interval.
$i = ct_test_control_job( 'control-i.example.net' );
ct_scan_request_control_check( $i['job_id'], $i['page'], 'dns_txt' );
$task_i = ct_test_control_claim();
$wpdb->update( $jobs, array( 'control_attempts' => 3, 'control_last_attempt_ms' => 1 ), array( 'job_id' => $i['job_id'] ) );
$over = ct_test_control_admit( $task_i );
ct_test_assert( 409 === $over->get_status() && 'budget_exhausted' === $over->get_data()['reason'] && 3 === (int) ct_scan_row( $i['job_id'] )->control_attempts, 'A fourth control admission was granted.' );
// Every check spent and the last result lost: maintenance blocks the job instead of leaving it waiting.
$wpdb->update( $jobs, array( 'control_lease_until' => gmdate( 'Y-m-d H:i:s', time() - 5 ) ), array( 'job_id' => $i['job_id'] ) );
ct_scan_maintenance_locked();
$ri = ct_scan_row( $i['job_id'] );
ct_test_assert( 'blocked' === $ri->status && 'target_control_failed' === $ri->error_code && null === $ri->control_page_hash, 'An exhausted job whose last result was lost was left waiting.' );
// An unconfirmed row is not admitted for a control check.
$j = ct_test_control_job( 'control-j.example.net' );
ct_scan_request_control_check( $j['job_id'], $j['page'], 'dns_txt' );
$task_j = ct_test_control_claim();
$wpdb->update( $jobs, array( 'confirmed_at' => null ), array( 'job_id' => $j['job_id'] ) );
$unconfirmed = ct_test_control_admit( $task_j );
ct_test_assert( 410 === $unconfirmed->get_status() && 'recipient_unconfirmed' === $unconfirmed->get_data()['reason'], 'An unconfirmed row was admitted for a control check.' );
// A revoked job's page is dead.
$k = ct_test_control_job( 'control-k.example.net' );
wp_set_current_user( 1 );
ct_scan_admin_revoke( $k['job_id'] );
ct_test_assert( 'control_link_invalid' === ct_scan_request_control_check( $k['job_id'], $k['page'], 'dns_txt' )->get_error_code(), 'A revoked job still accepted a control request.' );
// A claim whose recorded method is not one of the two is cancelled, not run.
$l = ct_test_control_job( 'control-l.example.net' );
$wpdb->update( $jobs, array( 'control_state' => 'requested', 'control_requested_method' => 'ftp' ), array( 'job_id' => $l['job_id'] ) );
ct_test_assert( null === ct_test_control_claim() && 'cancelled' === ct_scan_row( $l['job_id'] )->status, 'A control check with an unknown method was handed to the worker.' );
// One piece of target traffic at a time: a check in progress blocks scan claims and a scan blocks check claims.
$m1 = ct_test_control_job( 'control-m1.example.net' );
ct_scan_request_control_check( $m1['job_id'], $m1['page'], 'dns_txt' );
$task_m = ct_test_control_claim();
list( $q_id, $q_fields ) = ct_test_request( 'control-m2.example.net' );
$request_ids[] = $q_id;
ct_test_bind( $q_id, $q_fields );
$q_event = ct_scan_on_request_ready( $q_id, $q_fields );
$wpdb->update( $jobs, array( 'control_required' => 0 ), array( 'job_id' => $q_event['job_id'] ) );
ct_test_queue_job( $q_event['job_id'] );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'], 'A scan was claimed while a control check was in progress.' );
$wpdb->update( $jobs, array( 'control_state' => 'pending', 'control_lease_hash' => null ), array( 'job_id' => $m1['job_id'] ) );
ct_scan_request_control_check( $m1['job_id'], $m1['page'], 'dns_txt' );
$scan_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'];
ct_test_assert( is_array( $scan_claim ) && (int) $scan_claim['id'] === (int) $q_event['job_id'], 'The queued scan was not claimed.' );
ct_test_assert( null === ct_test_control_claim(), 'A control check was claimed while a scan was leased.' );

// ---- Recorded manual authority review ------------------------------------------------------------------
// Not while a check is in flight: its result could otherwise land on a job already released by review.
$wpdb->update( $jobs, array( 'status' => 'cancelled', 'error_code' => 'test_cleanup' ), array( 'job_id' => (int) $scan_claim['id'] ) );
$n = ct_test_control_job( 'control-n.example.net' );
ct_scan_request_control_check( $n['job_id'], $n['page'], 'dns_txt' );
$task_n = ct_test_control_claim();
ct_test_assert( $task_n && (int) $task_n['id'] === $n['job_id'], 'Fixture control claim failed.' );
wp_set_current_user( 1 );
$busy_review = ct_scan_admin_record_authority_review( $n['job_id'], 'Reviewed the signed engagement letter naming this website.' );
$rn = ct_scan_row( $n['job_id'] );
ct_test_assert( is_wp_error( $busy_review ) && 'authority_review_check_in_progress' === $busy_review->get_error_code() && 'awaiting_control' === $rn->status && 'checking' === $rn->control_state && null === $rn->control_verified_at, 'An authority review was recorded while a control check was in flight.' );
$wpdb->update( $jobs, array( 'status' => 'cancelled', 'error_code' => 'test_cleanup', 'control_state' => 'none' ), array( 'job_id' => $n['job_id'] ) );

$f = ct_test_control_job( 'control-f.example.net' );
wp_set_current_user( 0 );
ct_test_assert( 'authority_review_forbidden' === ct_scan_admin_record_authority_review( $f['job_id'], str_repeat( 'Reviewed the signed engagement letter. ', 2 ) )->get_error_code(), 'An anonymous caller recorded an authority review.' );
wp_set_current_user( 1 );
ct_test_assert( 'authority_review_evidence_required' === ct_scan_admin_record_authority_review( $f['job_id'], 'too short' )->get_error_code(), 'A review without evidence was recorded.' );
ct_test_assert( 'authority_review_evidence_required' === ct_scan_admin_record_authority_review( $f['job_id'], str_repeat( 'x', 1001 ) )->get_error_code(), 'An oversized review note was recorded.' );
ct_test_assert( 'awaiting_control' === ct_scan_row( $f['job_id'] )->status, 'A rejected review changed the job.' );
ct_test_assert( true === ct_scan_admin_record_authority_review( $f['job_id'], '<b>Reviewed</b> the signed engagement letter naming this website.' ), 'A valid authority review was refused.' );
$row = ct_scan_row( $f['job_id'] );
$ev = json_decode( $row->control_evidence, true );
ct_test_assert( 'queued' === $row->status && 'manual_review' === $row->control_method && ! empty( $row->control_verified_at ) && $row->control_valid_until === $row->authorization_expires_at, 'The review did not release the job with an expiry.' );
ct_test_assert( 1 === $ev['reviewer_id'] && 'fixture_admin' === $ev['reviewer'] && $ev['target'] === $f['fields']['target'] && 'Reviewed the signed engagement letter naming this website.' === $ev['evidence'] && ! empty( $ev['reviewed_at'] ) && $ev['valid_until'] === $row->authorization_expires_at, 'The review record omits reviewer, evidence, target, time or expiry.' );
ct_test_assert( is_wp_error( ct_scan_admin_record_authority_review( $f['job_id'], 'A second review of the same job should not be possible.' ) ), 'A queued job accepted another review.' );
// An expired review ends the authorization.
$wpdb->update( $jobs, array( 'control_valid_until' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ), array( 'job_id' => $f['job_id'] ) );
ct_test_assert( null === ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'] && 'cancelled' === ct_scan_row( $f['job_id'] )->status, 'An expired authority review still allowed a claim.' );
// A job that never required control cannot be reviewed into the control path.
$wpdb->update( $jobs, array( 'status' => 'awaiting_control', 'control_required' => 0 ), array( 'job_id' => $f['job_id'] ) );
ct_test_assert( is_wp_error( ct_scan_admin_record_authority_review( $f['job_id'], 'Reviewing a job that does not require control should fail.' ) ), 'A review was recorded for a job that does not require control.' );

// A row without the control_required value (an incomplete upgrade) is treated as requiring control.
$missing = (object) array( 'control_verified_at' => null );
ct_test_assert( ct_scan_control_required( $missing ) && ct_scan_control_required( (object) array( 'control_required' => null ) ) && ! ct_scan_control_required( (object) array( 'control_required' => '0' ) ), 'A missing control_required value was treated as not required.' );

foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "Target control checks passed.\n";
