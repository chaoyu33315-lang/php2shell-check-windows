<?php
/**
 * Disposable WordPress + MariaDB integration checks for the MU plugin.
 * Run only with the repository's `fixture-only` Docker Compose environment.
 */
require __DIR__ . '/support.php';

// Canonical scope normalization and control-character rejection.
ct_test_assert( 'https://example.com/' === ct_scan_normalize_target( 'https://EXAMPLE.com/' ), 'Canonical origin must have lowercase host and trailing slash.' );
foreach ( array( "https://example.com/\n", 'https://example.com/path', 'https://127.0.0.1/', 'https://user@example.com/', 'https://example.com:8443/' ) as $bad_target ) {
	ct_test_assert( is_wp_error( ct_scan_normalize_target( $bad_target ) ), 'Invalid target accepted: ' . bin2hex( $bad_target ) );
}

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
$mail_calls = array();
$mail_mode = true;
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail_calls, &$mail_mode ) {
	$mail_calls[] = $atts;
	return $mail_mode;
}, 10, 2 );

// A new accepted request creates one confirmation-gated immutable job.
list( $request_id, $fields ) = ct_test_request( 'queue-fixture.example.net' );
$request_ids[] = $request_id;
$event = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( is_array( $event ) && 'awaiting_confirmation' === $event['status'], 'Accepted request was not queued for confirmation.' );
ct_test_assert( 1 === (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE request_id=%d", $request_id ) ), 'Expected exactly one durable job.' );
$row = ct_scan_row( $event['job_id'] );
ct_test_assert( hash( 'sha256', $fields['target'] ) === $row->scope_hash, 'Scope hash must cover the exact canonical target.' );
ct_test_assert( 'accepted' === $row->confirmation_email_status, 'Confirmation mail acceptance state was not recorded.' );
ct_test_assert( false !== strpos( $mail_calls[0]['message'], 'token=' ), 'Confirmation link missing from the captured fixture email.' );
ct_test_assert( 1 === preg_match( '/[?&]stop=([a-f0-9]{64})/', $mail_calls[0]['message'], $stop_match ), 'Stop link missing from the captured fixture email.' );
ct_test_assert( 1 === preg_match( '/token=([a-f0-9]{64})/', $mail_calls[0]['message'], $confirm_match ) && $confirm_match[1] !== $stop_match[1], 'Stop and confirmation tokens must differ.' );
ct_test_assert( hash( 'sha256', $stop_match[1] ) === $row->stop_token_hash && false === strpos( wp_json_encode( $row ), $stop_match[1] ), 'Only the stop token hash may be stored.' );

// Duplicate hook delivery is database-idempotent even when the event meta is absent.
delete_post_meta( $request_id, '_ct_scan_event_recorded' );
$duplicate = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( ! is_wp_error( $duplicate ) && ! empty( $duplicate['duplicate'] ) && (int) $duplicate['job_id'] === (int) $event['job_id'], 'Duplicate event created a second job or changed state.' );

// Customer stop: wrong tokens fail, a finished job is not reopened, and a stopped job can never be claimed or started.
list( $stop_id, $stop_fields ) = ct_test_request( 'stop-fixture.example.net' );
$request_ids[] = $stop_id;
$mail_before = count( $mail_calls );
$stop_event = ct_scan_on_request_ready( $stop_id, $stop_fields );
preg_match( '/[?&]stop=([a-f0-9]{64})/', $mail_calls[ $mail_before ]['message'], $stop_match );
$stop_token = $stop_match[1];
$stop_row = ct_scan_row_by_stop_hash( hash( 'sha256', $stop_token ) );
ct_test_assert( $stop_row && (int) $stop_row->job_id === (int) $stop_event['job_id'], 'Stop token must resolve only to its own job.' );
ct_test_assert( is_wp_error( ct_scan_customer_stop( $stop_event['job_id'], str_repeat( 'a', 64 ) ) ), 'A wrong stop token was accepted.' );
ct_test_assert( is_wp_error( ct_scan_customer_stop( $event['job_id'], $stop_token ) ), 'A stop token stopped a different job.' );
ct_test_assert( 'awaiting_confirmation' === ct_scan_row( $stop_event['job_id'] )->status, 'A rejected stop changed job state.' );
ct_test_queue_job( $stop_event['job_id'] );
$stop_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$stop_claimed = $stop_claim->get_data()['job'];
ct_test_assert( (int) $stop_claimed['id'] === (int) $stop_event['job_id'], 'Fixture expected the stop job to be claimed.' );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $stop_event['job_id'], $stop_token ), 'A leased job was not stopped by its customer.' );
$stopped = ct_scan_row( $stop_event['job_id'] );
ct_test_assert( 'cancelled' === $stopped->status && 'customer_stopped' === $stopped->error_code && empty( $stopped->lease_hash ) && empty( $stopped->revoked_at ), 'Customer stop must cancel and clear the lease without operator revocation.' );
ct_test_assert( 'cancelled' === get_post_meta( $stop_id, '_ct_scan_status', true ), 'Request status did not record the stop.' );
$late_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $stop_claimed['id'], 'lease' => $stop_claimed['lease'], 'scope_hash' => $stop_claimed['scope_hash'] ) );
ct_test_assert( 410 === $late_start->get_status(), 'A stopped job was started by a stale lease.' );
$late_result = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', array( 'id' => $stop_claimed['id'], 'lease' => $stop_claimed['lease'], 'scope_hash' => $stop_claimed['scope_hash'], 'outcome' => 'completed', 'result' => ct_test_result( $stop_fields['target'] ), 'error' => '', 'checker_revision' => str_repeat( 'a', 40 ) ) );
ct_test_assert( 410 === $late_result->get_status(), 'A stopped job accepted a late result.' );
ct_test_assert( 'already_stopped' === ct_scan_customer_stop( $stop_event['job_id'], $stop_token ), 'Repeated stop must be idempotent.' );
$no_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $no_claim->get_status() && empty( $no_claim->get_data()['job'] ), 'A stopped job must never be claimed again.' );

// Confirmed queue: claim, start-before-work, validated result, and exact receipt retry.
ct_test_queue_job( $event['job_id'] );
$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $claim->get_status() && is_array( $claim->get_data()['job'] ), 'Signed claim did not return a job.' );
$claimed = $claim->get_data()['job'];
ct_test_assert( $claimed['target'] === $fields['target'] && is_int( $claimed['expires_at'] ) && is_int( $claimed['lease_until'] ), 'Claim fields or Unix timestamps are misaligned.' );
$start_payload = array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'] );
$start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', $start_payload );
ct_test_assert( 200 === $start->get_status() && true === $start->get_data()['ok'], 'Start callback was not acknowledged.' );
$run = array(
	'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'], 'outcome' => 'completed',
	'result' => ct_test_result( $fields['target'] ), 'error' => '', 'checker_revision' => str_repeat( 'a', 40 ),
);
// A completed result is not credible unless the guard admitted at least one request for the job.
$unadmitted = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 409 === $unadmitted->get_status() && 'no_admission' === $unadmitted->get_data()['error'] && 'running' === ct_scan_row( $claimed['id'] )->status, 'A completed result was accepted for a job that never had a request admitted.' );
ct_test_assert( 200 === ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'], 'kind' => 'http' ) )->get_status(), 'Fixture admission was refused.' );
$result = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $result->get_status() && true === $result->get_data()['ok'], 'Valid checker receipt was not acknowledged.' );
$retry = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $retry->get_status(), 'An exact receipt retry must be idempotent.' );
$changed = $run;
$changed['result']['title'] = 'Different valid receipt';
$conflict = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $changed );
ct_test_assert( 409 === $conflict->get_status(), 'Changed receipt must conflict.' );
$stale = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), null, time() - 301 );
ct_test_assert( 401 === $stale->get_status(), 'Stale HMAC timestamp must be rejected.' );
$replay_nonce = bin2hex( random_bytes( 16 ) );
$replay1 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
$replay2 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
ct_test_assert( 200 === $replay1->get_status() && 409 === $replay2->get_status(), 'Authenticated nonce replay was not rejected.' );

// Reports preserve old result snapshots, escape evidence, freeze after first send, and separate acceptance from delivery.
$stored = ct_scan_row( $event['job_id'] );
$snapshot = ct_test_result( $fields['target'] );
$snapshot['php2shell_rules_as_of'] = '2024-02-29';
$wpdb->update( $jobs, array( 'result_json' => wp_json_encode( $snapshot ) ), array( 'job_id' => (int) $event['job_id'] ) );
$stored = ct_scan_row( $event['job_id'] );
ct_test_assert( is_wp_error( ct_scan_validate_result( $snapshot, $stored ) ), 'New receipts must match current configured rules date.' );
ct_test_assert( ! is_wp_error( ct_scan_validate_result( $snapshot, $stored, true ) ), 'Stored report snapshot must remain valid after rules-date changes.' );
$admin_details = ct_scan_admin_result_details( $stored );
ct_test_assert( false !== strpos( $admin_details, 'Private stored PHP2Shell evidence' ) && false === strpos( $admin_details, '<script>' ), 'Private result details must render escaped evidence for reviewers.' );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $event['job_id'], 'Reviewed the remaining service scope.' ), 'Manual remainder did not save.' );
$preview = ct_scan_build_report_body( ct_scan_row( $event['job_id'] ) );
ct_test_assert( ! is_wp_error( $preview ) && false !== strpos( $preview, '2024-02-29' ), 'Reviewed report did not retain the frozen rule snapshot.' );
ct_test_assert( false === strpos( $preview, '<script>' ), 'HTML in observed evidence must not appear as executable markup.' );
ct_test_assert( true === ct_scan_admin_send_report( $event['job_id'] ), 'Reviewed report send was not accepted by the isolated mail fixture.' );
ct_test_assert( 'accepted' === ct_scan_row( $event['job_id'] )->report_notification_status, 'Report transport and delivery state were conflated.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $event['job_id'], 'Edited after send' ) ), 'Report details must freeze after a send attempt.' );
ct_test_assert( true === ct_scan_admin_record_delivery( $event['job_id'] ), 'Independently confirmed delivery did not persist.' );

// An expired, never-confirmed request cannot receive detailed findings, even after manual review.
list( $unconfirmed_id, $unconfirmed_fields ) = ct_test_request( 'unconfirmed-report-fixture.example.net' );
$request_ids[] = $unconfirmed_id;
$unconfirmed_event = ct_scan_on_request_ready( $unconfirmed_id, $unconfirmed_fields );
$wpdb->update( $jobs, array( 'status' => 'expired', 'error_code' => 'confirmation_expired', 'finished_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null ), array( 'job_id' => (int) $unconfirmed_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unconfirmed_event['job_id'], 'Operator notes entered after expiry.' ), 'Unconfirmed fixture manual notes failed.' );
$mail_count = count( $mail_calls );
$unconfirmed_send = ct_scan_admin_send_report( $unconfirmed_event['job_id'] );
ct_test_assert( is_wp_error( $unconfirmed_send ) && 'report_recipient_unconfirmed' === $unconfirmed_send->get_error_code(), 'An unconfirmed recipient was allowed a detailed report.' );
ct_test_assert( count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unconfirmed_event['job_id'] )->report_notification_status, 'A refused unconfirmed report must not send or change send state.' );

// Unknown mail outcomes remain one-shot; independently confirmed delivery can still be recorded.
list( $unknown_id, $unknown_fields ) = ct_test_request( 'unknown-mail-fixture.example.net' );
$request_ids[] = $unknown_id;
$unknown_event = ct_scan_on_request_ready( $unknown_id, $unknown_fields );
ct_test_queue_job( $unknown_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $unknown_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'No remaining work was performed in this fixture.' ), 'Unknown-mail fixture manual notes failed.' );
$mail_mode = false;
$mail_count = count( $mail_calls );
$fail_send_state_once = true;
$fail_send_state_filter = static function ( $query ) use ( &$fail_send_state_once, $jobs ) {
	if ( $fail_send_state_once && false !== strpos( $query, "SET `report_notification_status` = 'unknown'" ) && false !== strpos( $query, $jobs ) ) {
		$fail_send_state_once = false;
		return preg_replace( '/ WHERE /', ' WHERE 1=0 AND ', $query, 1 );
	}
	return $query;
};
add_filter( 'query', $fail_send_state_filter );
$write_failure = ct_scan_admin_send_report( $unknown_event['job_id'] );
remove_filter( 'query', $fail_send_state_filter );
ct_test_assert( is_wp_error( $write_failure ) && count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'A failed durable one-time send write must not send email.' );
$unknown_send = ct_scan_admin_send_report( $unknown_event['job_id'] );
ct_test_assert( is_wp_error( $unknown_send ) && 'unknown' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'Unconfirmed mail must remain unknown and must not be retried.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'Altered content' ) ), 'Report contents changed after an unknown send outcome.' );
ct_test_assert( true === ct_scan_admin_record_delivery( $unknown_event['job_id'] ), 'Independent proof must allow recording delivery from unknown state.' );
$mail_mode = true;

// The recorded terms hash is compared case-insensitively at report time (the job stores it lowercased).
list( $upper_id, $upper_fields ) = ct_test_request( 'upper-hash-report-fixture.example.net' );
$request_ids[] = $upper_id;
update_post_meta( $upper_id, '_ct_terms_sha256', strtoupper( get_post_meta( $upper_id, '_ct_terms_sha256', true ) ) );
$upper_event = ct_scan_on_request_ready( $upper_id, $upper_fields );
ct_test_assert( is_array( $upper_event ), 'A request with an upper-case terms hash was refused.' );
ct_test_queue_job( $upper_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $upper_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $upper_event['job_id'], 'No remaining work was performed in this fixture.' ), 'Upper-case hash fixture manual notes failed.' );
ct_test_assert( true === ct_scan_admin_send_report( $upper_event['job_id'] ), 'An upper-case recorded terms hash blocked the reviewed report.' );

// Old requests are never backfilled, and any changed saved target permanently cancels authorization.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'legacy-fixture.example.net' );
$request_ids[] = $legacy_id;
delete_post_meta( $legacy_id, '_ct_terms_saved' );
$legacy_event = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
ct_test_assert( is_wp_error( $legacy_event ) && ! $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$jobs} WHERE request_id=%d", $legacy_id ) ), 'A legacy request without the durable acceptance marker was backfilled.' );

list( $changed_id, $changed_fields ) = ct_test_request( 'changed-target-fixture.example.net' );
$request_ids[] = $changed_id;
$changed_event = ct_scan_on_request_ready( $changed_id, $changed_fields );
ct_test_assert( ! is_wp_error( $changed_event ), 'Changed-target fixture setup failed.' );
update_post_meta( $changed_id, '_ct_scan_target', 'https://different-fixture.example.net/' );
ct_test_assert( ! ct_scan_authorization_is_live( ct_scan_row( $changed_event['job_id'] ) ), 'A changed saved target remained authorized.' );
ct_test_queue_job( $changed_event['job_id'] );
$changed_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $changed_claim->get_status() && null === $changed_claim->get_data()['job'] && 'cancelled' === ct_scan_row( $changed_event['job_id'] )->status, 'A changed-target job was claimable instead of being canceled.' );

// Revocation while leased prevents start; an expired running lease is terminal and never rescanned.
list( $revoked_id, $revoked_fields ) = ct_test_request( 'revoked-fixture.example.net' );
$request_ids[] = $revoked_id;
$revoked_event = ct_scan_on_request_ready( $revoked_id, $revoked_fields );
ct_test_queue_job( $revoked_event['job_id'] );
$revoked_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$revoked_job = $revoked_claim->get_data()['job'];
ct_test_assert( is_array( $revoked_job ), 'Expected to claim the revocation fixture.' );
ct_test_assert( true === ct_scan_admin_revoke( $revoked_job['id'] ), 'Admin revocation did not persist.' );
$revoked_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $revoked_job['id'], 'lease' => $revoked_job['lease'], 'scope_hash' => $revoked_job['scope_hash'] ) );
ct_test_assert( 410 === $revoked_start->get_status() && 'cancelled' === ct_scan_row( $revoked_job['id'] )->status, 'Revoked authorization allowed worker start.' );

list( $lease_id, $lease_fields ) = ct_test_request( 'expired-lease-fixture.example.net' );
$request_ids[] = $lease_id;
$lease_event = ct_scan_on_request_ready( $lease_id, $lease_fields );
ct_test_queue_job( $lease_event['job_id'] );
$lease_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_job = $lease_claim->get_data()['job'];
ct_test_assert( is_array( $lease_job ), 'Expected to claim the expired-lease fixture.' );
$lease_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $lease_job['id'], 'lease' => $lease_job['lease'], 'scope_hash' => $lease_job['scope_hash'] ) );
ct_test_assert( 200 === $lease_start->get_status(), 'Expired-lease fixture did not enter running state.' );
$wpdb->update( $jobs, array( 'lease_until' => gmdate( 'Y-m-d H:i:s', time() - 5 ) ), array( 'job_id' => (int) $lease_job['id'] ) );
$after_expiry_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_row = ct_scan_row( $lease_job['id'] );
ct_test_assert( 200 === $after_expiry_claim->get_status() && null === $after_expiry_claim->get_data()['job'] && 'failed_unknown' === $lease_row->status && 1 === (int) $lease_row->attempts, 'An expired running lease was automatically rescanned or not marked unknown.' );

// Calendar-based retention clears result/manual content at 12 months, and only removes the exact private linked request at 3 years.
list( $retention_id, $retention_fields ) = ct_test_request( 'retention-fixture.example.net' );
$request_ids[] = $retention_id;
$retention_event = ct_scan_on_request_ready( $retention_id, $retention_fields );
$old_finished = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-13 months' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => $old_finished, 'terms_accepted_at' => $old_finished, 'result_json' => '{}', 'manual_remainder_notes' => 'private notes' ), array( 'job_id' => (int) $retention_event['job_id'] ) );
ct_test_maintain();
$retained = ct_scan_row( $retention_event['job_id'] );
ct_test_assert( $retained && null === $retained->result_json && null === $retained->manual_remainder_notes && get_post( $retention_id ), '12-month cleanup must clear result/manual data but retain the request evidence.' );
$three_years = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-3 years -1 day' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => $three_years, 'finished_at' => $three_years, 'closed_at' => $three_years, 'created_at' => $three_years, 'retain_until' => null ), array( 'job_id' => (int) $retention_event['job_id'] ) );
$hold_delete = static function ( $check, $post ) use ( $retention_id ) {
	return (int) $retention_id === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $hold_delete, 10, 2 );
ct_test_maintain();
remove_filter( 'pre_delete_post', $hold_delete, 10 );
ct_test_assert( ct_scan_row( $retention_event['job_id'] ) && get_post( $retention_id ) && '' === ct_scan_row( $retention_event['job_id'] )->contact_email && '' === ct_scan_row( $retention_event['job_id'] )->contact_name, 'Failed three-year post deletion must retain the job link while scrubbing contact fields.' );
ct_test_maintain();
ct_test_assert( ! ct_scan_row( $retention_event['job_id'] ) && ! get_post( $retention_id ), 'Three-year cleanup must remove the exact linked private request and job.' );

// Remove only records created by this test.
foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "WordPress integration checks passed.\n";
