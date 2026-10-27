<?php
/**
 * Run with CT_TEST_POLICY=strict and CT_TEST_COPY=1 (see evidence.php): the terms version requires bound
 * evidence, and the verified contact receives an accepted copy.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
$mail = array();
$mail_mode = true;
$captured_attachments = array();
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail, &$mail_mode, &$captured_attachments ) {
	$mail[] = $atts;
	foreach ( (array) ( $atts['attachments'] ?? array() ) as $path ) {
		$captured_attachments[] = array( 'name' => basename( $path ), 'bytes' => file_get_contents( $path ) );
	}
	if ( 'throw' === $mail_mode ) {
		throw new RuntimeException( 'injected mail fault' );
	}
	return $mail_mode;
}, 10, 2 );

// The version is listed as requiring bound evidence: an unbound acceptance is refused, with no job.
list( $unbound_id, $unbound_fields ) = ct_test_request( 'strict-unbound.example.net' );
$request_ids[] = $unbound_id;
$refused = ct_scan_on_request_ready( $unbound_id, $unbound_fields );
ct_test_assert( is_wp_error( $refused ) && 'ct_scan_binding_required' === get_post_meta( $unbound_id, '_ct_scan_status_detail', true ), 'An unbound acceptance for a bound-only version was queued.' );
ct_test_assert( 0 === (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE request_id = %d", $unbound_id ) ), 'A job exists for an unbound acceptance of a bound-only version.' );

// A bound acceptance is queued; the mailbox confirmation then sends the accepted copy to the verified contact only.
list( $request_id, $fields ) = ct_test_request( 'strict-bound.example.net', 'verified.customer@example.com' );
$request_ids[] = $request_id;
$meta = ct_test_bind( $request_id, $fields );
update_post_meta( $request_id, '_ct_ref', 'direct' );
$event = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( is_array( $event ), 'The bound acceptance was not queued.' );
$confirmation_mails = count( $mail );
$unconfirmed = ct_scan_send_accepted_copy( $event['job_id'] );
ct_test_assert( is_wp_error( $unconfirmed ) && count( $mail ) === $confirmation_mails && 'not_sent' === ct_scan_row( $event['job_id'] )->accepted_copy_status, 'An accepted copy was sent before the mailbox was confirmed.' );
ct_test_queue_job( $event['job_id'] );
$sent = ct_scan_send_accepted_copy( $event['job_id'] );
ct_test_assert( 'sent' === $sent && count( $mail ) === $confirmation_mails + 1, 'The accepted copy was not sent after confirmation.' );
$copy = $mail[ count( $mail ) - 1 ];
$to = (array) $copy['to'];
ct_test_assert( array( 'verified.customer@example.com' ) === array_values( $to ), 'The accepted copy went to someone other than the verified contact.' );
ct_test_assert( false !== strpos( $copy['message'], $meta['_ct_terms_sha256'] ) && false !== strpos( $copy['message'], $meta['_ct_summary_sha256'] ) && false !== strpos( $copy['message'], 'Website (scan scope): https://strict-bound.example.net/' ) && false !== strpos( $copy['message'], $meta['_ct_summary_text'] ), 'The accepted copy omits the hashes or the Target Summary.' );
$attachment = end( $captured_attachments );
ct_test_assert( $attachment && $attachment['bytes'] === $meta['_ct_terms_snapshot'] && hash( 'sha256', $attachment['bytes'] ) === $meta['_ct_terms_sha256'] && 0 === strpos( $attachment['name'], 'accepted-terms-' . $event['job_id'] . '-2026-10-21-r2-' ), 'The attached terms are not the exact retained bytes.' );
ct_test_assert( 'accepted' === ct_scan_row( $event['job_id'] )->accepted_copy_status && 'queued' === ct_scan_row( $event['job_id'] )->status, 'The copy changed the job state or was not recorded as transport-accepted.' );
ct_test_assert( empty( glob( sys_get_temp_dir() . '/ctat-*' ) ), 'A temporary copy of the terms was left on disk.' );

// Idempotent: a duplicate confirmation callback sends nothing more, and cannot touch the scan.
$count = count( $mail );
ct_test_assert( 'already_handled' === ct_scan_send_accepted_copy( $event['job_id'] ) && count( $mail ) === $count, 'The accepted copy was sent twice.' );

// Failure and fault handling: an uncertain outcome is never resent and never affects the job.
foreach ( array( false, 'throw' ) as $mode ) {
	list( $fid, $ffields ) = ct_test_request( 'strict-fault-' . ( $mode ? 'throw' : 'false' ) . '.example.net' );
	$request_ids[] = $fid;
	ct_test_bind( $fid, $ffields );
	$fevent = ct_scan_on_request_ready( $fid, $ffields );
	ct_test_queue_job( $fevent['job_id'] );
	$mail_mode = $mode;
	$result = ct_scan_send_accepted_copy( $fevent['job_id'] );
	$mail_mode = true;
	$count = count( $mail );
	ct_test_assert( 'unknown' === $result && 'unknown' === ct_scan_row( $fevent['job_id'] )->accepted_copy_status && 'queued' === ct_scan_row( $fevent['job_id'] )->status, 'A mail failure was reported as sent or changed the job.' );
	ct_test_assert( 'already_handled' === ct_scan_send_accepted_copy( $fevent['job_id'] ) && count( $mail ) === $count, 'An uncertain accepted copy was resent automatically.' );
}

// The recorded terms hash is compared case-insensitively at send time (the job stores it lowercased).
list( $upper_id, $upper_fields ) = ct_test_request( 'strict-upper.example.net' );
$request_ids[] = $upper_id;
$upper_meta = ct_test_bind( $upper_id, $upper_fields );
update_post_meta( $upper_id, '_ct_terms_sha256', strtoupper( $upper_meta['_ct_terms_sha256'] ) );
$upper_event = ct_scan_on_request_ready( $upper_id, $upper_fields );
ct_test_assert( is_array( $upper_event ), 'A bound acceptance with an upper-case terms hash was refused.' );
ct_test_queue_job( $upper_event['job_id'] );
$count = count( $mail );
ct_test_assert( 'sent' === ct_scan_send_accepted_copy( $upper_event['job_id'] ) && count( $mail ) === $count + 1, 'An upper-case recorded terms hash blocked the accepted copy.' );

// The strict policy requires target control: confirmation leaves the job awaiting control and still sends the copy.
list( $ctl_id, $ctl_fields ) = ct_test_request( 'strict-awaiting-control.example.net', 'control.customer@example.com' );
$request_ids[] = $ctl_id;
ct_test_bind( $ctl_id, $ctl_fields );
$count = count( $mail );
$ctl_event = ct_scan_on_request_ready( $ctl_id, $ctl_fields );
ct_test_assert( is_array( $ctl_event ) && 1 === (int) ct_scan_row( $ctl_event['job_id'] )->control_required && 1 === preg_match( '/token=([a-f0-9]{64})/', $mail[ $count ]['message'], $ctl_m ), 'The control-required fixture job or its confirmation mail is missing.' );
list( , $ctl_status ) = ct_scan_confirm_job( $ctl_event['job_id'], $ctl_m[1] );
$ctl_row = ct_scan_row( $ctl_event['job_id'] );
ct_test_assert( 200 === $ctl_status && 'awaiting_control' === $ctl_row->status && 'accepted' === $ctl_row->accepted_copy_status && array( 'control.customer@example.com' ) === array_values( (array) $mail[ count( $mail ) - 1 ]['to'] ), 'Confirming a job that awaits target control did not send the accepted copy.' );

// A job that is no longer live when the copy would be sent gets none, and its copy state is untouched.
foreach ( array( 'cancelled', 'revoked', 'evidence_changed' ) as $how ) {
	list( $dead_id, $dead_fields ) = ct_test_request( 'strict-dead-' . str_replace( '_', '-', $how ) . '.example.net' );
	$request_ids[] = $dead_id;
	ct_test_bind( $dead_id, $dead_fields );
	$dead_event = ct_scan_on_request_ready( $dead_id, $dead_fields );
	ct_test_queue_job( $dead_event['job_id'] );
	if ( 'cancelled' === $how ) {
		$wpdb->update( $jobs, array( 'status' => 'cancelled', 'error_code' => 'customer_stop' ), array( 'job_id' => $dead_event['job_id'] ) );
	} elseif ( 'revoked' === $how ) {
		$wpdb->update( $jobs, array( 'revoked_at' => ct_scan_utc_now() ), array( 'job_id' => $dead_event['job_id'] ) );
	} else {
		update_post_meta( $dead_id, '_ct_summary_text', wp_slash( ct_test_summary( $dead_fields ) . "Note: edited afterwards\n" ) );
	}
	$count = count( $mail );
	$dead = ct_scan_send_accepted_copy( $dead_event['job_id'] );
	ct_test_assert( is_wp_error( $dead ) && count( $mail ) === $count && 'not_sent' === ct_scan_row( $dead_event['job_id'] )->accepted_copy_status, "An accepted copy was sent for a job that is no longer live ($how)." );
}

// The requirement is frozen into each job. A job created before the version was listed as requiring
// bound evidence keeps working when the configuration later requires it, and one created bound keeps
// needing it: configuration can neither cancel nor relax an authorization already given.
$wpdb->query( "UPDATE {$jobs} SET status = 'cancelled', error_code = 'test_cleanup' WHERE status IN ('queued','leased','running')" );
list( $old_id, $old_fields ) = ct_test_request( 'strict-frozen.example.net' );
$request_ids[] = $old_id;
ct_test_bind( $old_id, $old_fields );
$old_event = ct_scan_on_request_ready( $old_id, $old_fields );
ct_test_queue_job( $old_event['job_id'] );
ct_test_assert( 1 === (int) ct_scan_row( $old_event['job_id'] )->bound_required, 'A job created under a bound-only version did not freeze that requirement.' );
foreach ( array( '_ct_terms_binding', '_ct_terms_snapshot', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $key ) {
	delete_post_meta( $old_id, $key );
}
$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'];
ct_test_assert( null === $claim && 'cancelled' === ct_scan_row( $old_event['job_id'] )->status, 'Removing the retained evidence did not end a job that was created bound.' );
// A job that predates the requirement (frozen not-required, no evidence) keeps working under the strict config.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'strict-predates.example.net' );
$request_ids[] = $legacy_id;
ct_test_bind( $legacy_id, $legacy_fields );
$legacy_event = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
foreach ( array( '_ct_terms_binding', '_ct_terms_snapshot', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $key ) {
	delete_post_meta( $legacy_id, $key );
}
$wpdb->update( $jobs, array( 'bound_required' => 0, 'summary_sha256' => null ), array( 'job_id' => $legacy_event['job_id'] ) );
ct_test_queue_job( $legacy_event['job_id'] );
$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'];
ct_test_assert( is_array( $claim ) && (int) $claim['id'] === (int) $legacy_event['job_id'], 'A job that predates the bound-evidence requirement was cancelled by it.' );
ct_test_end_job( $legacy_event['job_id'] );

// A cancelled (stopped) job still keeps its record; the copy does not resurrect or alter it.
foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "Strict evidence checks passed.\n";
