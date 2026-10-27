<?php
/**
 * Closure, retention periods, preservation holds and deletion tombstones. Disposable fixture only.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
// Leftovers of an aborted earlier run of this script.
$wpdb->query( "DELETE FROM {$jobs} WHERE job_id >= 888000000 OR job_id BETWEEN 887000000 AND 887999999" );
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() );
$request_ids = array();
add_filter( 'pre_wp_mail', '__return_true' );

function ct_test_old( $modifier ) {
	return ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( $modifier )->format( 'Y-m-d H:i:s' );
}

/** A job in $status whose acceptance and closure are the given ages. */
function ct_test_aged_job( $host, $status, $accepted, $closed, $version = '2026-10-21-r2' ) {
	global $wpdb, $request_ids;
	list( $request_id, $fields ) = ct_test_request( $host );
	$request_ids[] = $request_id;
	$event = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_array( $event ), 'Retention fixture job was not created.' );
	$update = array( 'status' => $status, 'terms_accepted_at' => ct_test_old( $accepted ), 'created_at' => ( new DateTimeImmutable( ct_test_old( $accepted ), new DateTimeZone( 'UTC' ) ) )->modify( '+30 seconds' )->format( 'Y-m-d H:i:s' ), 'terms_version' => $version, 'confirmation_token_hash' => null );
	if ( null !== $closed ) {
		$update['finished_at'] = ct_test_old( $closed );
		$update['result_json'] = '{"fixture":true}';
		$update['manual_remainder_notes'] = 'private findings';
	}
	$wpdb->update( ct_scan_jobs_table(), $update, array( 'job_id' => (int) $event['job_id'] ) );
	return array( 'job_id' => (int) $event['job_id'], 'request_id' => $request_id );
}

function ct_test_exists( $job ) {
	return (bool) ct_scan_row( $job['job_id'] );
}

// ---- Closure is explicit, and only terminal jobs close ---------------------------------------------------
list( $live_request, $live_fields ) = ct_test_request( 'ret-live.example.net' );
$request_ids[] = $live_request;
$live_event = ct_scan_on_request_ready( $live_request, $live_fields );
ct_test_queue_job( $live_event['job_id'] );
$live = array( 'job_id' => (int) $live_event['job_id'], 'request_id' => $live_request );
$closing = ct_test_aged_job( 'ret-closing.example.net', 'failed', '-1 day', '-1 hour' );
$blocked = ct_test_aged_job( 'ret-blocked.example.net', 'blocked', '-2 days', '-1 day' );
ct_test_maintain();
$row = ct_scan_row( $closing['job_id'] );
ct_test_assert( $row->closed_at === $row->finished_at && ! empty( $row->retain_until ), 'A finished job was not stamped closed with a deletion date.' );
ct_test_assert( null === ct_scan_row( $live['job_id'] )->closed_at && null === ct_scan_row( $live['job_id'] )->retain_until, 'A job that can still run was stamped closed.' );
ct_test_assert( ! empty( ct_scan_row( $blocked['job_id'] )->closed_at ), 'A blocked job was not closed.' );
ct_test_assert( ct_test_exists( $live ) && get_post( $live['request_id'] ), 'A job that can still run was deleted or closed by retention.' );

// r2: three years from acceptance. Other versions: six years after closure.
$r2 = ct_scan_row( $closing['job_id'] );
ct_test_assert( $r2->retain_until === ( new DateTimeImmutable( $r2->terms_accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'r2 evidence is not kept three years from acceptance.' );
$newer = ct_test_aged_job( 'ret-newer.example.net', 'cancelled', '-1 year', '-1 month', '2027-06-01-r3' );
ct_test_maintain();
$nr = ct_scan_row( $newer['job_id'] );
ct_test_assert( $nr->retain_until === ( new DateTimeImmutable( $nr->closed_at, new DateTimeZone( 'UTC' ) ) )->modify( '+6 years' )->format( 'Y-m-d H:i:s' ), 'A newer version is not kept six years after closure.' );

// The date is set at closure (and can only be extended when it comes due): a later change of the stored acceptance date does not move it.
$fixed = $nr->retain_until;
$wpdb->update( $jobs, array( 'terms_accepted_at' => ct_test_old( '-9 years' ) ), array( 'job_id' => $newer['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_scan_row( $newer['job_id'] )->retain_until === $fixed, 'The deletion date was recomputed after closure.' );

// An accepted-but-unverified request that expires is closed too.
list( $unverified_id, $unverified_fields ) = ct_test_request( 'ret-unverified.example.net' );
$request_ids[] = $unverified_id;
$unverified = ct_scan_on_request_ready( $unverified_id, $unverified_fields );
$wpdb->update( $jobs, array( 'confirmation_expires_at' => ct_test_old( '-1 hour' ) ), array( 'job_id' => $unverified['job_id'] ) );
ct_test_maintain();
$u = ct_scan_row( $unverified['job_id'] );
ct_test_assert( 'expired' === $u->status && ! empty( $u->closed_at ) && ! empty( $u->retain_until ), 'An unconfirmed request that expired was not closed with a deletion date.' );

// ---- Findings: twelve months after closure; evidence is kept ------------------------------------------------
$young = ct_test_aged_job( 'ret-young.example.net', 'completed', '-2 years', '-11 months' );
$old   = ct_test_aged_job( 'ret-old.example.net', 'completed', '-2 years', '-13 months' );
ct_test_maintain();
ct_test_assert( null !== ct_scan_row( $young['job_id'] )->result_json && null !== ct_scan_row( $young['job_id'] )->manual_remainder_notes, 'Findings were cleared before twelve months.' );
$o = ct_scan_row( $old['job_id'] );
ct_test_assert( null === $o->result_json && null === $o->manual_remainder_notes && ct_test_exists( $old ) && get_post( $old['request_id'] ), 'Findings were not cleared at twelve months, or the signed evidence went with them.' );

// ---- Evidence deadlines --------------------------------------------------------------------------------------
$edge_keep = ct_test_aged_job( 'ret-keep.example.net', 'failed', '-2 years -11 months', '-1 day' );
$edge_del  = ct_test_aged_job( 'ret-del.example.net', 'failed', '-3 years -1 day', '-1 day' );
$six_keep  = ct_test_aged_job( 'ret-six-keep.example.net', 'cancelled', '-6 years -2 days', '-5 years -11 months', '2027-06-01-r3' );
$six_del   = ct_test_aged_job( 'ret-six-del.example.net', 'cancelled', '-6 years -2 days', '-6 years -1 day', '2027-06-01-r3' );
ct_test_maintain();
ct_test_assert( ct_test_exists( $edge_keep ) && get_post( $edge_keep['request_id'] ), 'r2 evidence was deleted before three years.' );
ct_test_assert( ! ct_test_exists( $edge_del ) && ! get_post( $edge_del['request_id'] ), 'r2 evidence was not deleted after three years.' );
ct_test_assert( ct_test_exists( $six_keep ) && get_post( $six_keep['request_id'] ), 'Six-year evidence was deleted early.' );
ct_test_assert( ! ct_test_exists( $six_del ) && ! get_post( $six_del['request_id'] ), 'Six-year evidence was not deleted after its period.' );

// ---- Tombstones: identifiers only ----------------------------------------------------------------------------
$stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $edge_del['job_id'] ) );
ct_test_assert( $stone && (int) $stone->request_id === $edge_del['request_id'] && 'retention' === $stone->reason && 64 === strlen( $stone->scope_mac ), 'No tombstone recorded the deletion.' );
// The tombstone holds a keyed MAC of the scope, not the plain hash of the hostname (nobody reading a backup can test for a customer).
$plain = hash( 'sha256', 'https://ret-del.example.net/' );
ct_test_assert( $stone->scope_mac === ct_scan_tombstone_mac( $plain ) && $stone->scope_mac !== $plain && ! in_array( 'scope_hash', $wpdb->get_col( 'SHOW COLUMNS FROM ' . ct_scan_tombstones_table(), 0 ), true ) && false === strpos( wp_json_encode( $wpdb->get_results( 'SELECT * FROM ' . ct_scan_tombstones_table() ) ), $plain ), 'The tombstone exposes the plain scope hash.' );
ct_test_assert( ct_scan_tombstone_mac( $plain ) !== ct_scan_tombstone_mac( hash( 'sha256', 'https://other.example.net/' ) ), 'The scope MAC does not distinguish scopes.' );
$columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . ct_scan_tombstones_table(), 0 );
ct_test_assert( array() === array_intersect( $columns, array( 'contact_email', 'contact_name', 'target_origin', 'result_json', 'terms_hash', 'scope_hash' ) ), 'The tombstone table can hold personal or customer data.' );

// A restored backup brings the rows back: maintenance deletes them again.
$ghost = array( 'job_id' => $edge_del['job_id'], 'request_id' => $edge_del['request_id'], 'target_origin' => 'https://ret-del.example.net/', 'scope_hash' => $plain, 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-3 years -1 day' ), 'retention_checked_at' => ct_scan_utc_now(), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'restored@example.com', 'contact_name' => 'Restored Person', 'referrer' => 'direct', 'status' => 'failed', 'created_at' => $stone->created_at, 'finished_at' => ct_test_old( '-1 day' ), 'closed_at' => ct_test_old( '-1 day' ) );
$wpdb->insert( $jobs, $ghost );
$restored_post = wp_insert_post( array( 'import_id' => $edge_del['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $edge_del['request_id'], '_ct_scan_job_id', $edge_del['job_id'] );
update_post_meta( $edge_del['request_id'], '_ct_scan_identity', $stone->identity );
ct_test_assert( 32 === strlen( (string) $stone->identity ), 'The tombstone did not keep the opaque identity.' );
ct_test_assert( ct_test_exists( $edge_del ) && get_post( $edge_del['request_id'] ), 'Fixture failed to restore the deleted records.' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $edge_del ) && ! get_post( $edge_del['request_id'] ), 'A restored backup resurrected deleted records.' );
// A different job that merely reuses the identifier is not touched.
$wpdb->insert( $jobs, array_merge( $ghost, array( 'created_at' => ct_test_old( '-1 day' ), 'status' => 'failed', 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'other@example.com' ) ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $edge_del ), 'A job that is not the deleted one matched the tombstone.' );
$wpdb->delete( $jobs, array( 'job_id' => $edge_del['job_id'] ) );
// A post with the same id but another job id is not deleted either.
$other = wp_insert_post( array( 'import_id' => $six_del['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'unrelated' ) );
update_post_meta( $six_del['request_id'], '_ct_scan_job_id', 999999999 );
ct_test_maintain();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted a request that belongs to a different job.' );
// Same id and job id but not the same identity (a recycled id after a restore): untouched.
$six_stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $six_del['job_id'] ) );
update_post_meta( $six_del['request_id'], '_ct_scan_job_id', $six_del['job_id'] );
update_post_meta( $six_del['request_id'], '_ct_scan_identity', str_repeat( 'f', 32 ) );
ct_test_maintain();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted a request with a different identity.' );
// Same identity but a live job row now uses that request id: a recycled id must never reach a live record.
update_post_meta( $six_del['request_id'], '_ct_scan_identity', $six_stone->identity );
$wpdb->insert( $jobs, array( 'job_id' => 888000001, 'request_id' => $six_del['request_id'], 'target_origin' => 'https://recycled.example.net/', 'scope_hash' => str_repeat( 'c', 64 ), 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'live@example.com', 'contact_name' => 'Live', 'referrer' => 'direct', 'status' => 'awaiting_confirmation', 'created_at' => ct_test_old( '-1 hour' ) ) );
ct_test_maintain();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted the request of a live job that reuses its id.' );
$wpdb->delete( $jobs, array( 'job_id' => 888000001 ) );
// With no live row, a matching identity does delete a restored post, in any post status.
wp_update_post( array( 'ID' => $six_del['request_id'], 'post_status' => 'trash' ) );
ct_test_maintain();
ct_test_assert( ! get_post( $six_del['request_id'] ), 'A restored request in the trash was not deleted.' );
// Tombstones expire after the backup window, not before.
$wpdb->update( ct_scan_tombstones_table(), array( 'deleted_at' => ct_test_old( '-100 days' ) ), array( 'job_id' => $edge_del['job_id'] ) );
$wpdb->update( ct_scan_tombstones_table(), array( 'deleted_at' => ct_test_old( '-130 days' ) ), array( 'job_id' => $six_del['job_id'] ) );
ct_test_maintain();
ct_test_assert( null !== $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $edge_del['job_id'] ) ), 'A tombstone was purged inside the backup window.' );
ct_test_assert( null === $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $six_del['job_id'] ) ), 'A tombstone outlived the backup window.' );

// ---- Narrow preservation holds ---------------------------------------------------------------------------------
$held = ct_test_aged_job( 'ret-held.example.net', 'failed', '-3 years -1 day', '-13 months' );
wp_set_current_user( 0 );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_set_hold( $held['job_id'], 'Preserving records for dispute number 123.', 30 )->get_error_code(), 'An anonymous caller placed a hold.' );
$subscriber = wp_insert_user( array( 'user_login' => 'ct_ret_sub_' . wp_generate_password( 6, false ), 'user_pass' => wp_generate_password(), 'role' => 'subscriber' ) );
wp_set_current_user( (int) $subscriber );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_set_hold( $held['job_id'], 'Preserving records for dispute number 123.', 30 )->get_error_code() && 'hold_forbidden' === ct_scan_admin_release_hold( $held['job_id'] )->get_error_code(), 'A logged-in non-administrator managed a hold.' );
wp_set_current_user( 1 );
foreach ( array( array( 'too short', 30 ), array( str_repeat( 'x', 191 ), 30 ), array( 'Preserving records for dispute number 123.', 0 ), array( 'Preserving records for dispute number 123.', 731 ), array( 'Preserving records for dispute number 123.', 'forever' ), array( 'Preserving records for dispute number 123.', -5 ) ) as $i => $bad ) {
	ct_test_assert( 'hold_invalid' === ct_scan_admin_set_hold( $held['job_id'], $bad[0], $bad[1] )->get_error_code(), "Invalid hold case $i was accepted." );
}
ct_test_assert( true === ct_scan_admin_set_hold( $held['job_id'], '<b>Preserving</b> records for dispute number 123.', 30 ), 'A valid hold was refused.' );
$h = ct_scan_row( $held['job_id'] );
ct_test_assert( 'Preserving records for dispute number 123.' === $h->hold_reason && 1 === (int) $h->hold_set_by && $h->hold_until > ct_scan_utc_now() && $h->hold_until <= ct_test_old( '+31 days' ), 'The hold does not record its purpose, setter and expiry.' );
ct_test_maintain();
$h = ct_scan_row( $held['job_id'] );
ct_test_assert( $h && null !== $h->result_json && null !== $h->manual_remainder_notes && get_post( $held['request_id'] ), 'A held job lost records.' );
// A hold that just expired still preserves for the grace period, so nothing vanishes the minute it lapses.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-1 minute' ) ), array( 'job_id' => $held['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $held ) && null !== ct_scan_row( $held['job_id'] )->result_json, 'A hold that expired a minute ago released its records at once.' );
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-4 days' ) ), array( 'job_id' => $held['job_id'] ) );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $held ) && ! get_post( $held['request_id'] ), 'An expired hold still pinned the record after its grace period.' );
// The tombstone path honours a hold too: a restored row under a hold is kept.
$restore_held = ct_test_aged_job( 'ret-restore-held.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $restore_held ), 'Fixture expected the job to be deleted first.' );
$rstone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $restore_held['job_id'] ) );
$wpdb->insert( $jobs, array( 'job_id' => $restore_held['job_id'], 'request_id' => $restore_held['request_id'], 'target_origin' => 'https://ret-restore-held.example.net/', 'scope_hash' => hash( 'sha256', 'https://ret-restore-held.example.net/' ), 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'held@example.com', 'contact_name' => 'Held', 'referrer' => 'direct', 'status' => 'failed', 'created_at' => $rstone->created_at, 'hold_reason' => 'Preserving this restored record for a dispute.', 'hold_until' => ct_test_old( '+30 days' ) ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $restore_held ), 'A restored job under a hold was deleted by its tombstone.' );
$wpdb->delete( $jobs, array( 'job_id' => $restore_held['job_id'] ) );

// ---- Untrustworthy dates and doubtful rows are kept, never deleted --------------------------------------------
$zero_r2 = ct_test_aged_job( 'ret-zero-r2.example.net', 'failed', '-3 years -1 day', '-1 hour' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => '0000-00-00 00:00:00', 'closed_at' => null, 'retain_until' => null ), array( 'job_id' => $zero_r2['job_id'] ) );
$zero_new = ct_test_aged_job( 'ret-zero-new.example.net', 'cancelled', '-1 year', '-1 hour', '2027-06-01-r3' );
$wpdb->update( $jobs, array( 'finished_at' => '0000-00-00 00:00:00', 'closed_at' => '0000-00-00 00:00:00', 'retain_until' => null ), array( 'job_id' => $zero_new['job_id'] ) );
$garbled = ct_test_aged_job( 'ret-garbled.example.net', 'failed', '-3 years -1 day', '-1 hour' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => '1999-01-01 00:00:00', 'closed_at' => null, 'retain_until' => null ), array( 'job_id' => $garbled['job_id'] ) );
ct_test_maintain();
ct_test_maintain();
foreach ( array( $zero_r2, $zero_new, $garbled ) as $case ) {
	$r = ct_scan_row( $case['job_id'] );
	ct_test_assert( $r && null === $r->retain_until && get_post( $case['request_id'] ), 'A job with an untrustworthy date was given a deletion date or deleted.' );
}
ct_test_assert( null !== ct_scan_row( $zero_new['job_id'] )->result_json, 'Findings were cleared on the strength of a zero date.' );
// A stored date earlier than the one derived today, or earlier than three years after creation, is not honoured.
$tampered = ct_test_aged_job( 'ret-tampered.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $tampered ), 'Fixture expected a normal due job to be deleted.' );
$early = ct_test_aged_job( 'ret-early.example.net', 'failed', '-2 years', '-1 day' );
ct_test_maintain();
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $early['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $early ) && get_post( $early['request_id'] ), 'A retain_until earlier than three years after creation (or the derived date) deleted the evidence.' );
$er = ct_scan_row( $early['job_id'] );
ct_test_assert( $er->retain_until === ( new DateTimeImmutable( $er->terms_accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A stored date short of the derived one was not extended to the derived date.' );
// The derived-date check alone (the creation floor passes): accepted two years ago, created four years ago.
$early2 = ct_test_aged_job( 'ret-early2.example.net', 'failed', '-2 years', '-1 day' );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-4 years' ) ), array( 'job_id' => $early2['job_id'] ) );
ct_test_maintain();
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $early2['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $early2 ), 'A retain_until earlier than the date derived from the row deleted the evidence.' );
// The creation floor alone: a record created long after its acceptance date is not deleted on that date.
$late_created = ct_test_aged_job( 'ret-late-created.example.net', 'failed', '-3 years -1 day', '-1 day' );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-2 days' ) ), array( 'job_id' => $late_created['job_id'] ) ); // still before its closure
ct_test_maintain();
ct_test_assert( ct_test_exists( $late_created ), 'A record created after its stated acceptance date was deleted on that date.' );
// ... but it is not kept forever either: it gets three full years from creation (later than the promised
// three years from acceptance), a definite date.
$lc = ct_scan_row( $late_created['job_id'] );
ct_test_assert( $lc->retain_until === ( new DateTimeImmutable( $lc->created_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A legacy record created after its stated acceptance did not get a definite deadline three years after creation.' );
// The same case once that later date has come: kept on the run that finds the shorter date, deleted when the later one arrives.
$late_due = ct_test_aged_job( 'ret-late-due.example.net', 'failed', '-3 years -5 days', '-1 day' );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-3 years -1 hour' ) ), array( 'job_id' => $late_due['job_id'] ) );
ct_test_maintain();
$ld = ct_scan_row( $late_due['job_id'] );
ct_test_assert( $ld && get_post( $late_due['request_id'] ) && $ld->retain_until === ( new DateTimeImmutable( $ld->created_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A legacy record created after its acceptance was deleted at the acceptance-based date, or its date was not extended.' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $late_due ) && ! get_post( $late_due['request_id'] ), 'A legacy record created after its acceptance was never deleted at its extended date.' );
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '+1 year' ) ), array( 'job_id' => $early['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $early ) && ct_scan_row( $early['job_id'] )->retain_until > ct_test_old( '+1 day' ), 'A later stored deletion date was shortened.' );
// A job that can still run is never deleted even if its dates say it is due.
$running = ct_test_aged_job( 'ret-running.example.net', 'awaiting_confirmation', '-3 years -1 day', null );
$wpdb->update( $jobs, array( 'closed_at' => ct_test_old( '-1 day' ), 'retain_until' => ct_test_old( '-1 hour' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'confirmation_expires_at' => ct_test_old( '+1 day' ) ), array( 'job_id' => $running['job_id'] ) );
ct_test_maintain();
$rr = ct_scan_row( $running['job_id'] );
ct_test_assert( $rr && get_post( $running['request_id'] ) && null === $rr->closed_at && null === $rr->retain_until, 'A job that can still run was deleted, or kept a closure stamp, because its dates said so.' );
// Reopening clears the closure stamp so the old date cannot delete it later.
$reopen = ct_test_aged_job( 'ret-reopen.example.net', 'failed', '-1 day', '-1 hour' );
ct_test_maintain();
ct_test_assert( null !== ct_scan_row( $reopen['job_id'] )->retain_until, 'Fixture expected a closed job.' );
$wpdb->update( $jobs, array( 'status' => 'awaiting_confirmation' ), array( 'job_id' => $reopen['job_id'] ) );
ct_test_maintain();
$ro = ct_scan_row( $reopen['job_id'] );
ct_test_assert( null === $ro->closed_at && null === $ro->retain_until, 'Reopening a job left its old closure and deletion date.' );
// A terminal job with no finished_at is closed now, not left open.
$nofinish = ct_test_aged_job( 'ret-nofinish.example.net', 'cancelled', '-1 day', null );
ct_test_maintain();
ct_test_assert( ! empty( ct_scan_row( $nofinish['job_id'] )->closed_at ), 'A terminal job without finished_at was never closed.' );

// ---- Version rules and period floors ----------------------------------------------------------------------------
foreach ( array( '2026-01-01-r1' => true, '2026-10-21-r1' => true, '2026-10-21-r2' => true, '2026-10-21-r3' => false, '2026-10-22-r1' => false, '2027-06-01-r3' => false, 'weird' => false, '' => false, '2026-10-21-r2 ' => false, '2020-01-01-r9999' => false ) as $version => $legacy ) {
	ct_test_assert( $legacy === ct_scan_is_legacy_version( $version ), "Version '$version' was classified wrongly." );
}
ct_test_assert( 3 === ct_scan_clamp_years( 1 ) && 3 === ct_scan_clamp_years( 0 ) && 3 === ct_scan_clamp_years( 'x' ) && 3 === ct_scan_clamp_years( -6 ) && 3 === ct_scan_clamp_years( null ) && 6 === ct_scan_clamp_years( 6 ) && 10 === ct_scan_clamp_years( '10' ), 'The three-year floor does not hold.' );
$old_version = ct_test_aged_job( 'ret-old-version.example.net', 'failed', '-2 years', '-1 day', '2026-01-01-r1' );
$weird_version = ct_test_aged_job( 'ret-weird-version.example.net', 'failed', '-2 years', '-1 day', 'weird' );
ct_test_maintain();
$ov = ct_scan_row( $old_version['job_id'] );
$wv = ct_scan_row( $weird_version['job_id'] );
ct_test_assert( $ov->retain_until === ( new DateTimeImmutable( $ov->terms_accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A pre-r2 acceptance is not kept three years from acceptance.' );
ct_test_assert( $wv->retain_until === ( new DateTimeImmutable( $wv->closed_at, new DateTimeZone( 'UTC' ) ) )->modify( '+6 years' )->format( 'Y-m-d H:i:s' ), 'An unrecognised version did not get the longer period.' );

// ---- Deleting in any post status; bounded work per run ----------------------------------------------------------
$trashed = ct_test_aged_job( 'ret-trashed.example.net', 'failed', '-3 years -1 day', '-1 day' );
wp_update_post( array( 'ID' => $trashed['request_id'], 'post_status' => 'trash' ) );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $trashed ) && ! get_post( $trashed['request_id'] ), 'A trashed request (with the contact details and contract) outlived its deleted job.' );
$batch = array();
for ( $i = 0; $i < 53; $i++ ) {
	$batch[] = ct_test_aged_job( "ret-batch-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
}
ct_test_maintain();
$remaining = count( array_filter( $batch, 'ct_test_exists' ) );
ct_test_assert( $remaining >= 3 && $remaining < 53, "A single run did not bound its deletions ($remaining of 53 remain)." );
ct_test_maintain();
ct_test_maintain();
ct_test_assert( 0 === count( array_filter( $batch, 'ct_test_exists' ) ), 'The remaining due jobs were not deleted on later runs.' );

// Release works; a damaged hold (purpose without expiry) preserves rather than deletes.
$rel = ct_test_aged_job( 'ret-release.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_scan_admin_set_hold( $rel['job_id'], 'Preserving records for dispute number 456.', 10 );
ct_test_assert( 'hold_changed' === ct_scan_admin_release_hold( $rel['job_id'] )->get_error_code() && 'hold_changed' === ct_scan_admin_release_hold( $rel['job_id'], str_repeat( 'a', 64 ) )->get_error_code() && empty( ct_scan_row( $rel['job_id'] )->hold_released_at ), 'A release without the identity of the hold shown was accepted.' );
ct_test_assert( true === ct_scan_admin_release_hold( $rel['job_id'], ct_scan_hold_identity( ct_scan_row( $rel['job_id'] ) ) ), 'Release failed.' );
$released = ct_scan_row( $rel['job_id'] );
ct_test_assert( 'Preserving records for dispute number 456.' === $released->hold_reason && $released->hold_until <= ct_scan_utc_now() && $released->hold_until >= ct_test_old( '-1 minute' ) && 1 === (int) $released->hold_released_by && ! empty( $released->hold_released_at ), 'Release did not end the hold now (keeping its purpose) or did not record who released it.' );
ct_test_assert( 'hold_unavailable' === ct_scan_admin_release_hold( $rel['job_id'] )->get_error_code() && 'hold_unavailable' === ct_scan_admin_release_hold( 999999999 )->get_error_code() && 'hold_unavailable' === ct_scan_admin_release_hold( 0 )->get_error_code(), 'Releasing a hold that does not exist reported success.' );
$damaged = ct_test_aged_job( 'ret-damaged.example.net', 'failed', '-3 years -1 day', '-1 day' );
$wpdb->update( $jobs, array( 'hold_reason' => 'Purpose without an expiry (damaged).', 'hold_until' => null ), array( 'job_id' => $damaged['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $rel ) && get_post( $rel['request_id'] ) && null !== ct_scan_row( $rel['job_id'] )->result_json && ct_test_exists( $damaged ), 'A released hold did not preserve the records for the grace period, or a damaged hold allowed deletion.' );
// Once the grace period after the release has passed, the job is deleted as usual.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-3 days -1 minute' ) ), array( 'job_id' => $rel['job_id'] ) );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $rel ) && ! get_post( $rel['request_id'] ) && ct_test_exists( $damaged ), 'A released hold kept the records after its grace period, or a damaged hold allowed deletion.' );
// Releasing a hold that already expired keeps its own end (a release never lengthens a hold).
$lapsed = ct_test_aged_job( 'ret-lapsed.example.net', 'failed', '-1 day', '-1 hour' );
ct_scan_admin_set_hold( $lapsed['job_id'], 'Preserving records for dispute number 789.', 10 );
$lapsed_until = ct_test_old( '-2 days' );
$wpdb->update( $jobs, array( 'hold_until' => $lapsed_until ), array( 'job_id' => $lapsed['job_id'] ) );
ct_test_assert( true === ct_scan_admin_release_hold( $lapsed['job_id'], ct_scan_hold_identity( ct_scan_row( $lapsed['job_id'] ) ) ) && $lapsed_until === ct_scan_row( $lapsed['job_id'] )->hold_until, 'Releasing an expired hold lengthened it.' );
wp_set_current_user( 0 );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_release_hold( $damaged['job_id'] )->get_error_code() && ct_test_exists( $damaged ) && ! empty( ct_scan_row( $damaged['job_id'] )->hold_reason ), 'An anonymous caller released a hold.' );


// ---- Second review: no starvation, identity backfill, damaged holds, far-future dates ---------------------------
// Rows with a stored date short of what today's rules require (here: a legacy acceptance a year before its
// record was created) are extended, not deleted, and rows with contradictory dates are judged once a day:
// neither can hide a due job.
$doubtful = array();
for ( $i = 0; $i < 52; $i++ ) {
	$d = ct_test_aged_job( "ret-doubtful-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
	$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-2 days' ) ), array( 'job_id' => $d['job_id'] ) ); // still before its closure
	$doubtful[] = $d;
}
// A row whose dates contradict each other (closed before it was created) sorts first and is kept, judged at most daily.
$due_behind = ct_test_aged_job( 'ret-behind-doubtful.example.net', 'failed', '-3 years -2 days', '-2 days' );
$behind_accepted = ct_test_old( '-3 years -2 days' );
$behind_closed   = ( new DateTimeImmutable( $behind_accepted, new DateTimeZone( 'UTC' ) ) )->modify( '+10 seconds' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => $behind_accepted, 'created_at' => ( new DateTimeImmutable( $behind_accepted, new DateTimeZone( 'UTC' ) ) )->modify( '+30 seconds' )->format( 'Y-m-d H:i:s' ), 'finished_at' => $behind_closed, 'closed_at' => $behind_closed, 'retain_until' => ct_test_old( '-1 year' ) ), array( 'job_id' => $due_behind['job_id'] ) );
// Due only after all the doubtful rows in date order (so a 50-row window would never reach it).
$really_due = ct_test_aged_job( 'ret-really-due.example.net', 'failed', '-3 years -2 hours', '-1 hour' );
for ( $run = 0; $run < 3; $run++ ) {
	ct_test_maintain();
}
ct_test_assert( ! ct_test_exists( $really_due ), 'Doubtful rows starved a due job.' );
ct_test_assert( 52 === count( array_filter( $doubtful, 'ct_test_exists' ) ) && ct_test_exists( $due_behind ), 'Doubtful rows were deleted.' );
ct_test_assert( ! empty( ct_scan_row( $due_behind['job_id'] )->retention_checked_at ), 'A doubtful row was not marked as examined.' );
// The rows whose stored date was short of three years after creation were given that later, definite date.
foreach ( $doubtful as $d ) {
	$dr = ct_scan_row( $d['job_id'] );
	ct_test_assert( $dr->retain_until === ( new DateTimeImmutable( $dr->created_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A row with a stored date short of three years after creation was not given a definite later date.' );
}
foreach ( array_merge( $doubtful, array( $due_behind ) ) as $d ) {
	$wpdb->delete( $jobs, array( 'job_id' => $d['job_id'] ) );
	wp_delete_post( $d['request_id'], true );
}

// A job from before the identity existed gets one (adopting what its request carries), so a restore can be recognised.
$legacy = ct_test_aged_job( 'ret-preidentity.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'identity' => null, 'retain_until' => ct_test_old( '+1 day' ) ), array( 'job_id' => $legacy['job_id'] ) );
delete_post_meta( $legacy['request_id'], '_ct_scan_identity' );
ct_test_maintain();
$identity = ct_scan_row( $legacy['job_id'] )->identity;
ct_test_assert( 1 === preg_match( '/\A[a-f0-9]{32}\z/', (string) $identity ) && $identity === ct_scan_meta_string( $legacy['request_id'], '_ct_scan_identity' ), 'A job without an identity was not given one together with its request.' );
$carried = ct_test_aged_job( 'ret-carried.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'identity' => null, 'retain_until' => ct_test_old( '+1 day' ) ), array( 'job_id' => $carried['job_id'] ) );
update_post_meta( $carried['request_id'], '_ct_scan_identity', str_repeat( 'a', 32 ) );
ct_test_maintain();
ct_test_assert( str_repeat( 'a', 32 ) === ct_scan_row( $carried['job_id'] )->identity && str_repeat( 'a', 32 ) === ct_scan_meta_string( $carried['request_id'], '_ct_scan_identity' ), 'An identity the request already carried was replaced.' );
// Then delete it and restore the post: it is recognised and deleted again.
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 hour' ) ), array( 'job_id' => $legacy['job_id'] ) );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $legacy ) && ! get_post( $legacy['request_id'] ), 'Fixture expected the pre-identity job to be deleted.' );
wp_insert_post( array( 'import_id' => $legacy['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $legacy['request_id'], '_ct_scan_job_id', $legacy['job_id'] );
update_post_meta( $legacy['request_id'], '_ct_scan_identity', $identity );
ct_test_maintain();
ct_test_assert( ! get_post( $legacy['request_id'] ), 'The restored request of a pre-identity job was not deleted again.' );
// The duplicate-event path restores the identity meta of a request that lost it.
list( $dup_id, $dup_fields ) = ct_test_request( 'ret-dup.example.net' );
$request_ids[] = $dup_id;
$dup_event = ct_scan_on_request_ready( $dup_id, $dup_fields );
$dup_identity = ct_scan_row( $dup_event['job_id'] )->identity;
ct_test_assert( 1 === preg_match( '/\A[a-f0-9]{32}\z/', (string) $dup_identity ) && $dup_identity === ct_scan_meta_string( $dup_id, '_ct_scan_identity' ), 'A new job does not carry its identity on the request.' );
delete_post_meta( $dup_id, '_ct_scan_identity' );
delete_post_meta( $dup_id, '_ct_scan_event_recorded' );
ct_scan_on_request_ready( $dup_id, $dup_fields );
ct_test_assert( $dup_identity === ct_scan_meta_string( $dup_id, '_ct_scan_identity' ), 'The duplicate-event path left the request without its identity.' );

// A damaged hold (zero expiry) also protects the findings.
$zero_hold = ct_test_aged_job( 'ret-zero-hold.example.net', 'completed', '-2 years', '-13 months' );
$wpdb->update( $jobs, array( 'hold_reason' => 'Preserving for a dispute (damaged expiry).', 'hold_until' => '0000-00-00 00:00:00' ), array( 'job_id' => $zero_hold['job_id'] ) );
ct_test_maintain();
ct_test_assert( null !== ct_scan_row( $zero_hold['job_id'] )->result_json, 'A hold with a zero expiry did not protect the findings.' );

// A far-future creation date does not defeat the creation floor.
$future = ct_test_aged_job( 'ret-future.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'created_at' => '9999-01-01 00:00:00' ), array( 'job_id' => $future['job_id'] ) );
ct_test_maintain();
ct_test_assert( ct_test_exists( $future ) && ! ct_scan_valid_datetime( '9999-01-01 00:00:00' ) && ! ct_scan_valid_datetime( '10000-01-01 00:00:00' ), 'A far-future date was accepted.' );

// A restored request hidden behind many newer tombstones that point at live records is still found.
$buried = ct_test_aged_job( 'ret-buried.example.net', 'failed', '-3 years -2 days', '-2 days' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $buried ), 'Fixture expected the buried job to be deleted.' );
$buried_stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $buried['job_id'] ) );
for ( $i = 0; $i < 55; $i++ ) {
	$wpdb->insert( ct_scan_tombstones_table(), array( 'job_id' => 770000000 + $i, 'request_id' => 780000000 + $i, 'scope_mac' => str_repeat( 'd', 64 ), 'created_at' => ct_test_old( '-1 hour' ), 'deleted_at' => ct_test_old( '-1 minute' ), 'reason' => 'retention', 'identity' => bin2hex( random_bytes( 16 ) ) ) );
}
wp_insert_post( array( 'import_id' => $buried['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $buried['request_id'], '_ct_scan_job_id', $buried['job_id'] );
update_post_meta( $buried['request_id'], '_ct_scan_identity', $buried_stone->identity );
ct_test_maintain();
ct_test_assert( ! get_post( $buried['request_id'] ), 'Newer tombstones hid a restored request from cleanup.' );

wp_set_current_user( 1 );
// Placing a new hold clears the audit of an earlier release.
$reheld = ct_test_aged_job( 'ret-reheld.example.net', 'failed', '-1 day', '-1 hour' );
ct_scan_admin_set_hold( $reheld['job_id'], 'First preservation purpose for this job.', 10 );
ct_scan_admin_release_hold( $reheld['job_id'], ct_scan_hold_identity( ct_scan_row( $reheld['job_id'] ) ) );
ct_scan_admin_set_hold( $reheld['job_id'], 'Second preservation purpose for this job.', 10 );
$rh = ct_scan_row( $reheld['job_id'] );
ct_test_assert( null === $rh->hold_released_by && null === $rh->hold_released_at && 'Second preservation purpose for this job.' === $rh->hold_reason, 'A new hold kept the audit of an earlier release.' );

// ---- Fourth review: a second hold never shortens or replaces a standing one; identities; tombstone paging ---------
wp_set_current_user( 1 );
$long_hold = ct_test_aged_job( 'ret-long-hold.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $long_hold );
ct_test_assert( true === ct_scan_admin_set_hold( $long_hold['job_id'], 'Litigation hold for dispute number 2468.', 730 ), 'A 730-day hold was refused.' );
$lh = ct_scan_row( $long_hold['job_id'] );
$second_admin = wp_insert_user( array( 'user_login' => 'ct_ret_admin_' . wp_generate_password( 6, false ), 'user_pass' => wp_generate_password(), 'role' => 'administrator' ) );
wp_set_current_user( (int) $second_admin );
foreach ( array( 1, 729, 730 ) as $days ) {
	$second = ct_scan_admin_set_hold( $long_hold['job_id'], 'A different, later purpose for this job.', $days );
	$now_lh = ct_scan_row( $long_hold['job_id'] );
	ct_test_assert( is_wp_error( $second ) && 'hold_active' === $second->get_error_code() && $lh->hold_until === $now_lh->hold_until && $lh->hold_reason === $now_lh->hold_reason && (int) $lh->hold_set_by === (int) $now_lh->hold_set_by && $lh->hold_set_at === $now_lh->hold_set_at, "A second hold ($days days) replaced or shortened a standing hold, or lost its purpose or setter." );
}
ct_test_maintain();
ct_test_assert( ct_test_exists( $long_hold ) && get_post( $long_hold['request_id'] ), 'A due job lost its records after a refused second hold.' );
// Inside the grace period of an expired (unreleased) hold, a new hold is refused too: the original purpose and setter stay.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $long_hold['job_id'] ) );
$lh = ct_scan_row( $long_hold['job_id'] );
$grace_try = ct_scan_admin_set_hold( $long_hold['job_id'], 'A different, later purpose for this job.', 30 );
ct_test_assert( is_wp_error( $grace_try ) && 'hold_active' === $grace_try->get_error_code() && $lh->hold_until === ct_scan_row( $long_hold['job_id'] )->hold_until && $lh->hold_reason === ct_scan_row( $long_hold['job_id'] )->hold_reason, 'A hold in its grace period was replaced without being released.' );
ct_test_maintain();
ct_test_assert( ct_test_exists( $long_hold ), 'A job in its hold grace period was deleted.' );
// Released (still in grace): a new hold may be placed, and it never ends earlier than the released one.
ct_test_assert( true === ct_scan_admin_release_hold( $long_hold['job_id'], ct_scan_hold_identity( $lh ) ) && $lh->hold_until === ct_scan_row( $long_hold['job_id'] )->hold_until, 'Releasing an expired hold changed its end.' );
ct_test_assert( true === ct_scan_admin_set_hold( $long_hold['job_id'], 'A different, later purpose for this job.', 30 ), 'A new hold after a release was refused.' );
$lh2 = ct_scan_row( $long_hold['job_id'] );
ct_test_assert( 'A different, later purpose for this job.' === $lh2->hold_reason && (int) $second_admin === (int) $lh2->hold_set_by && $lh2->hold_until > ct_test_old( '+29 days' ) && null === $lh2->hold_released_at, 'A new hold after a release was not recorded with its own purpose and setter.' );
// A damaged state (released, yet an expiry still in the future) is never shortened.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '+300 days' ), 'hold_released_at' => ct_test_old( '-1 hour' ), 'hold_released_by' => 1 ), array( 'job_id' => $long_hold['job_id'] ) );
$lh3 = ct_scan_row( $long_hold['job_id'] );
$short = ct_scan_admin_set_hold( $long_hold['job_id'], 'A shorter purpose that must not win.', 5 );
ct_test_assert( is_wp_error( $short ) && $lh3->hold_until === ct_scan_row( $long_hold['job_id'] )->hold_until && $lh3->hold_reason === ct_scan_row( $long_hold['job_id'] )->hold_reason, 'A hold whose expiry is still in the future was shortened.' );
wp_set_current_user( 1 );
$wpdb->delete( $jobs, array( 'job_id' => $long_hold['job_id'] ) );

// A due job without its opaque identity is kept until the backfill gives it one (never a tombstone without identity).
$no_identity = (object) array( 'status' => 'failed', 'hold_reason' => null, 'hold_until' => null, 'terms_version' => '2026-10-21-r2', 'terms_accepted_at' => '2024-02-20 12:00:00', 'created_at' => '2024-02-20 12:00:30', 'closed_at' => '2024-02-29 12:00:00', 'retain_until' => '2027-02-20 12:00:00', 'identity' => null );
ct_test_assert( array( 'keep', null ) === ct_scan_deletion_decision( $no_identity, '2028-01-01 00:00:00' ), 'A job without an identity was judged deletable.' );
$no_identity->identity = '';
ct_test_assert( array( 'keep', null ) === ct_scan_deletion_decision( $no_identity, '2028-01-01 00:00:00' ), 'A job with an empty identity was judged deletable.' );
unset( $no_identity->identity );
ct_test_assert( array( 'keep', null ) === ct_scan_deletion_decision( $no_identity, '2028-01-01 00:00:00' ), 'A row read without its identity was judged deletable.' );
$no_identity->identity = str_repeat( 'a', 32 );
ct_test_assert( 'delete' === ct_scan_deletion_decision( $no_identity, '2028-01-01 00:00:00' )[0], 'Fixture expected the same job with an identity to be deletable.' );
$empty_identity = ct_test_aged_job( 'ret-empty-identity.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $empty_identity );
$wpdb->update( $jobs, array( 'identity' => '' ), array( 'job_id' => $empty_identity['job_id'] ) );
delete_post_meta( $empty_identity['request_id'], '_ct_scan_identity' );
ct_test_maintain();
$ei_stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $empty_identity['job_id'] ) );
ct_test_assert( ! $ei_stone || 1 === preg_match( '/\A[a-f0-9]{32}\z/', (string) $ei_stone->identity ), 'A job was deleted with an empty identity in its tombstone.' );
ct_test_assert( null === $wpdb->get_var( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . " WHERE reason = 'retention' AND (identity IS NULL OR identity = '')" ), 'A retention tombstone without an identity exists.' );
$wpdb->delete( $jobs, array( 'job_id' => $empty_identity['job_id'] ) );

// A due job whose linked post has no identity (empty or missing) while the job has one is kept whole.
foreach ( array( 'missing' => null, 'empty' => '' ) as $kind => $value ) {
	$blank = ct_test_aged_job( "ret-blank-post-{$kind}.example.net", 'failed', '-3 years -1 day', '-1 day' );
	ct_test_make_due( $blank );
	if ( null === $value ) {
		delete_post_meta( $blank['request_id'], '_ct_scan_identity' );
	} else {
		update_post_meta( $blank['request_id'], '_ct_scan_identity', $value );
	}
	ct_test_maintain();
	$br = ct_scan_row( $blank['job_id'] );
	ct_test_assert( $br && get_post( $blank['request_id'] ) && 'fixture@example.com' === $br->contact_email && null === $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $blank['job_id'] ) ), "A job was (partly) deleted although its linked post's identity is {$kind}." );
	$wpdb->delete( $jobs, array( 'job_id' => $blank['job_id'] ) );
}

// Restored rows that cannot be acted on (held, leased) never starve a later restored row in the tombstone loop.
$restored_base = array( 'target_origin' => 'https://ret-starve.example.net/', 'scope_hash' => hash( 'sha256', 'https://ret-starve.example.net/' ), 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-4 years' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'restored@example.com', 'contact_name' => 'Restored', 'referrer' => 'direct', 'status' => 'failed', 'created_at' => ct_test_old( '-4 years' ), 'retention_checked_at' => ct_scan_utc_now() );
for ( $i = 0; $i < 56; $i++ ) {
	$extra = 9 === $i % 10 ? array( 'status' => 'running', 'attempts' => 1, 'lease_hash' => str_repeat( 'b', 64 ), 'lease_until' => ct_test_old( '+1 hour' ) ) : array( 'hold_reason' => 'Preserving this restored record for a dispute.', 'hold_until' => ct_test_old( '+30 days' ) );
	ct_test_assert( 1 === $wpdb->insert( $jobs, array_merge( $restored_base, array( 'job_id' => 887000100 + $i, 'request_id' => 886000100 + $i ), $extra ) ), 'Fixture insert of a restored row failed: ' . $wpdb->last_error );
	$wpdb->insert( ct_scan_tombstones_table(), array( 'job_id' => 887000100 + $i, 'request_id' => 886000100 + $i, 'scope_mac' => ct_scan_tombstone_mac( $restored_base['scope_hash'] ), 'created_at' => $restored_base['created_at'], 'deleted_at' => ct_test_old( '-1 day' ), 'reason' => 'retention', 'identity' => bin2hex( random_bytes( 16 ) ) ) );
}
ct_test_assert( 1 === $wpdb->insert( $jobs, array_merge( $restored_base, array( 'job_id' => 887000200, 'request_id' => 886000200 ) ) ), 'Fixture insert of a restored row failed: ' . $wpdb->last_error );
$wpdb->insert( ct_scan_tombstones_table(), array( 'job_id' => 887000200, 'request_id' => 886000200, 'scope_mac' => ct_scan_tombstone_mac( $restored_base['scope_hash'] ), 'created_at' => $restored_base['created_at'], 'deleted_at' => ct_test_old( '-1 day' ), 'reason' => 'retention', 'identity' => bin2hex( random_bytes( 16 ) ) ) );
ct_scan_retention_run( true );
$starve_left = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$jobs} WHERE job_id BETWEEN 887000100 AND 887000155" );
ct_test_assert( ! ct_scan_row( 887000200 ) && 56 === $starve_left, "Held or leased restored rows starved a later restored row, or were deleted ($starve_left of 56 kept)." );
$wpdb->query( "DELETE FROM {$jobs} WHERE job_id BETWEEN 887000100 AND 887000200" );
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() . ' WHERE job_id BETWEEN 887000100 AND 887000200' );


// ---- Second round: floors, clock, ordering, locks -----------------------------------------------------------------
// Evidence retention for non-legacy versions can never be configured below six years; legacy never below three.
foreach ( array( 'six', '', '0', '1', '5', '5.9', '-6', 'NULL', 'TRUE', 'FALSE', 'ARRAY', '1e400', 'NaN' ) as $raw ) {
	$p = proc_open( array( PHP_BINARY, __DIR__ . '/retention-years.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'CT_TEST_EVIDENCE_YEARS' => $raw ) ) );
	$out = trim( stream_get_contents( $pp[1] ) );
	proc_close( $p );
	ct_test_assert( '2032-01-01 00:00:00 2028-01-01 00:00:00' === $out, "evidence_retention_years '$raw' gave '$out' instead of the six-year floor (legacy: three)." );
}
$p = proc_open( array( PHP_BINARY, __DIR__ . '/retention-years.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'CT_TEST_EVIDENCE_YEARS' => '8' ) ) );
ct_test_assert( '2034-01-01 00:00:00 2028-01-01 00:00:00' === trim( stream_get_contents( $pp[1] ) ), 'A longer configured retention was not honoured.' );
proc_close( $p );
// A retention period that would push the date past 2200 (where no date is trusted, so "kept forever") is clamped to 100 years.
$p = proc_open( array( PHP_BINARY, __DIR__ . '/retention-years.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'CT_TEST_EVIDENCE_YEARS' => '500' ) ) );
$capped = trim( stream_get_contents( $pp[1] ) );
proc_close( $p );
ct_test_assert( '2126-01-01 00:00:00 2028-01-01 00:00:00' === $capped && 100 === ct_scan_clamp_years( 500, 6 ) && 100 === ct_scan_clamp_years( '1e10', 6 ) && 100 === ct_scan_clamp_years( 100, 6 ) && 99 === ct_scan_clamp_years( 99, 6 ), "An oversized retention period was not clamped to 100 years ($capped)." );
ct_test_assert( 6 === ct_scan_clamp_years( 'six', 6 ) && 6 === ct_scan_clamp_years( null, 6 ) && 6 === ct_scan_clamp_years( 0, 6 ) && 6 === ct_scan_clamp_years( 1, 6 ) && 6 === ct_scan_clamp_years( true, 6 ) && 6 === ct_scan_clamp_years( array( 9 ), 6 ) && 7 === ct_scan_clamp_years( '7', 6 ) && 3 === ct_scan_clamp_years( 0, 1 ), 'The retention floors do not hold.' );

// A deletion is refused when the record appears to have closed before it was created (every other check passes).
$backwards = ct_test_aged_job( 'ret-backwards.example.net', 'failed', '-3 years -3 days', '-2 days' );
$accepted_at = ct_test_old( '-3 years -3 days' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => $accepted_at, 'created_at' => ( new DateTimeImmutable( $accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+30 seconds' )->format( 'Y-m-d H:i:s' ), 'finished_at' => ( new DateTimeImmutable( $accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+10 seconds' )->format( 'Y-m-d H:i:s' ) ), array( 'job_id' => $backwards['job_id'] ) );
ct_test_make_due( $backwards );
ct_test_maintain();
ct_test_assert( ct_test_exists( $backwards ) && get_post( $backwards['request_id'] ), 'A record that appeared to close before it was created was deleted.' );

// Nothing is deleted while the clock is earlier than a stored job timestamp (a clock jumped backwards, a bad restore).
$clocked = ct_test_aged_job( 'ret-clock.example.net', 'failed', '-3 years -1 day', '-1 day' );
$future_row = ct_test_aged_job( 'ret-future-row.example.net', 'queued', '-1 day', null );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '+10 days' ), 'authorization_expires_at' => ct_test_old( '+60 days' ) ), array( 'job_id' => $future_row['job_id'] ) );
$clock_closing = ct_test_aged_job( 'ret-clock-closing.example.net', 'cancelled', '-1 day', null ); // no finished_at: closure would stamp "now"
ct_test_maintain();
ct_test_assert( ct_test_exists( $clocked ) && get_post( $clocked['request_id'] ), 'Evidence was deleted although the clock was earlier than a stored job timestamp.' );
ct_test_assert( null === ct_scan_row( $clock_closing['job_id'] )->closed_at && null === ct_scan_row( $clocked['job_id'] )->closed_at && null === ct_scan_row( $clocked['job_id'] )->retain_until, 'A closure or deletion date was stamped while the clock could not be trusted.' );
ct_test_assert( ! ct_scan_clock_is_sane( ct_scan_utc_now() ) && ct_scan_clock_is_sane( ct_test_old( '+11 days' ) ), 'The clock sanity check does not compare with the newest stored timestamp.' );
$wpdb->delete( $jobs, array( 'job_id' => $future_row['job_id'] ) );
wp_delete_post( $future_row['request_id'], true );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $clocked ), 'Deletion did not resume once the clock was consistent.' );
ct_test_assert( ! empty( ct_scan_row( $clock_closing['job_id'] )->closed_at ), 'Closure was not stamped once the clock was consistent.' );
ct_test_assert( ! ct_scan_clock_is_sane( '1999-01-01 00:00:00' ) && ! ct_scan_clock_is_sane( '2300-01-01 00:00:00' ), 'Absurd clocks were accepted.' );

/** Stamp closure and the deletion date directly, without running a pass (the job is due as soon as retention runs). */
function ct_test_make_due( $job ) {
	global $wpdb;
	$row = ct_scan_row( $job['job_id'] );
	$closed = $row->finished_at;
	$row->closed_at = $closed;
	$wpdb->update( ct_scan_jobs_table(), array( 'closed_at' => $closed, 'retain_until' => ct_scan_retain_until( $row ), 'retention_checked_at' => null ), array( 'job_id' => (int) $job['job_id'] ) );
}

// Retention does not hold the queue lock across its work: each deletion takes it for that job only, and
// never deletes without it. (Stop waits up to three seconds for this lock; it must not queue behind a batch.)
$batch2 = array();
for ( $i = 0; $i < 12; $i++ ) {
	$batch2[] = ct_test_aged_job( "ret-lockseq-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
}
foreach ( $batch2 as $j ) {
	ct_test_make_due( $j );
}
$events = array();
$lockname = static function ( $sql ) use ( &$events, $jobs ) {
	if ( false !== strpos( $sql, "GET_LOCK('ctscan_" ) ) { $events[] = 'G'; }
	elseif ( false !== strpos( $sql, "RELEASE_LOCK('ctscan_" ) ) { $events[] = 'R'; }
	elseif ( 0 === strpos( ltrim( $sql ), "DELETE FROM `{$jobs}`" ) ) { $events[] = 'D'; }
	return $sql;
};
add_filter( 'query', $lockname );
ct_scan_retention_run( true );
remove_filter( 'query', $lockname );
$depth = 0; $max_deletes_per_hold = 0; $in_hold = 0; $unlocked_deletes = 0; $holds = 0;
foreach ( $events as $e ) {
	if ( 'G' === $e ) { ++$depth; ++$holds; $in_hold = 0; }
	elseif ( 'R' === $e ) { --$depth; }
	elseif ( 'D' === $e ) { if ( $depth < 1 ) { ++$unlocked_deletes; } ++$in_hold; $max_deletes_per_hold = max( $max_deletes_per_hold, $in_hold ); }
}
$deleted_now = 12 - count( array_filter( $batch2, 'ct_test_exists' ) );
ct_test_assert( 12 === $deleted_now && 0 === $unlocked_deletes && $max_deletes_per_hold <= 1 && $holds >= 12 && 0 === $depth, "Retention locking is wrong (deleted $deleted_now, unlocked $unlocked_deletes, max per hold $max_deletes_per_hold, holds $holds)." );

// A busy queue means "later", not an error and not a long wait; a second retention run cannot overlap the first.
$busy = ct_test_aged_job( 'ret-busy.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $busy );
$holder = proc_open( array( PHP_BINARY, __DIR__ . '/lock-holder.php', '1.5' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $hp, null, null );
ct_test_assert( is_resource( $holder ) && "locked\n" === fgets( $hp[1] ), 'The queue-lock holder did not start.' );
$started = microtime( true );
ct_scan_retention_run( true );
ct_test_assert( microtime( true ) - $started < 1.0 && ct_test_exists( $busy ), 'Retention waited for, or deleted under, a busy queue.' );
proc_close( $holder );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $busy ), 'Retention did not delete once the queue was free.' );
$busy2 = ct_test_aged_job( 'ret-busy2.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $busy2 );
$holder = proc_open( array( PHP_BINARY, __DIR__ . '/lock-holder.php', '1.5', 'retention' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $hp, null, null );
ct_test_assert( is_resource( $holder ) && "locked\n" === fgets( $hp[1] ), 'The retention-lock holder did not start.' );
ct_test_assert( false === ct_scan_retention_run( true ) && ct_test_exists( $busy2 ), 'A second retention run overlapped the first.' );
proc_close( $holder );
ct_test_assert( true === ct_scan_retention_run( true ) && ! ct_test_exists( $busy2 ), 'Retention did not run once the other run finished.' );
// Non-forced runs (the worker poll) are throttled to about one a minute.
delete_transient( 'ct_scan_retention_last' );
ct_test_assert( true === ct_scan_retention_run() && false === ct_scan_retention_run(), 'Retention is not throttled on the polling path.' );
delete_transient( 'ct_scan_retention_last' );
// A Stop is not held up by retention: it takes the same queue lock but nothing holds it for long.
$stopper = ct_test_aged_job( 'ret-stop.example.net', 'awaiting_confirmation', '-1 hour', null );
$wpdb->update( $jobs, array( 'confirmation_expires_at' => ct_test_old( '+1 day' ) ), array( 'job_id' => $stopper['job_id'] ) );
$stop_token = bin2hex( random_bytes( 32 ) );
$wpdb->update( $jobs, array( 'stop_token_hash' => hash( 'sha256', $stop_token ) ), array( 'job_id' => $stopper['job_id'] ) );
$many = array();
for ( $i = 0; $i < 20; $i++ ) { $many[] = ct_test_aged_job( "ret-stopbatch-$i.example.net", 'failed', '-3 years -1 day', '-1 day' ); ct_test_make_due( end( $many ) ); }
$started = microtime( true );
ct_scan_retention_run( true );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $stopper['job_id'], $stop_token ) && microtime( true ) - $started < 3.0, 'A Stop around a retention run failed or took too long.' );

// Deletion that cannot complete leaves the record (and its tombstone) rather than half-deleting.
$stuck = ct_test_aged_job( 'ret-stuck.example.net', 'failed', '-3 years -1 day', '-1 day' );
$block = static function ( $check, $post ) use ( $stuck ) {
	return (int) $stuck['request_id'] === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $block, 10, 2 );
ct_test_maintain();
remove_filter( 'pre_delete_post', $block, 10 );
$s = ct_scan_row( $stuck['job_id'] );
ct_test_assert( $s && get_post( $stuck['request_id'] ) && '' === $s->contact_email, 'A failed deletion lost the link between the job and its request.' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $stuck ) && ! get_post( $stuck['request_id'] ), 'The deletion was not completed on the next run.' );

// ---- Third review: extension instead of "never", clocks, shared budget, identities, leap days ----------------------
// A longer period configured after closure: the earlier stored date is not honoured; retain_until is extended
// (never shortened) and the records are deleted when the later date arrives.
$run_raised = static function () {
	$p = proc_open( array( PHP_BINARY, __DIR__ . '/retention-maintain.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'CT_TEST_EVIDENCE_YEARS' => '8', 'CT_TEST_LEGACY_YEARS' => '5' ) ) );
	$out = trim( stream_get_contents( $pp[1] ) );
	$err = trim( stream_get_contents( $pp[2] ) );
	proc_close( $p );
	ct_test_assert( 'maintained' === $out, "The raised-configuration maintenance run failed: $out $err" );
	wp_cache_flush(); // the other process changed the database behind this one's object cache
};
// (Dates before 2020 are refused as untrustworthy, so the case whose new date has already come is a legacy one.)
$raise_past   = ct_test_aged_job( 'ret-raise-past.example.net', 'failed', '-5 years -3 days', '-5 years -2 days' );
$raise_future = ct_test_aged_job( 'ret-raise-future.example.net', 'cancelled', '-6 years -3 days', '-6 years -2 days', '2027-06-01-r3' );
$raise_legacy = ct_test_aged_job( 'ret-raise-legacy.example.net', 'failed', '-3 years -2 days', '-1 day' );
foreach ( array( $raise_past, $raise_future, $raise_legacy ) as $j ) {
	ct_test_make_due( $j ); // stamped at closure under six (legacy: three) years: due now
}
$plus = static function ( $date, $years ) {
	return ( new DateTimeImmutable( $date, new DateTimeZone( 'UTC' ) ) )->modify( '+' . $years . ' years' )->format( 'Y-m-d H:i:s' );
};
$run_raised();
$rp = ct_scan_row( $raise_past['job_id'] );
$rf = ct_scan_row( $raise_future['job_id'] );
$rl = ct_scan_row( $raise_legacy['job_id'] );
ct_test_assert( $rp && $rf && $rl && get_post( $raise_past['request_id'] ) && get_post( $raise_future['request_id'] ) && get_post( $raise_legacy['request_id'] ), 'Evidence was deleted at the date fixed under a shorter configuration.' );
ct_test_assert( $rp->retain_until === $plus( $rp->terms_accepted_at, 5 ) && $rf->retain_until === $plus( $rf->closed_at, 8 ) && $rl->retain_until === $plus( $rl->terms_accepted_at, 5 ), "retain_until was not extended to the longer configured period ({$rp->retain_until} {$rf->retain_until} {$rl->retain_until}; checked {$rp->retention_checked_at})." );
$run_raised();
ct_test_assert( ! ct_test_exists( $raise_past ) && ! get_post( $raise_past['request_id'] ), 'Evidence was not deleted once the extended date arrived.' );
ct_test_assert( ct_test_exists( $raise_future ) && ct_test_exists( $raise_legacy ), 'Evidence was deleted before its extended date.' );
// Back under the shorter configuration, the extended dates are not shortened again.
ct_test_maintain();
ct_test_assert( ct_test_exists( $raise_future ) && ct_test_exists( $raise_legacy ) && $rf->retain_until === ct_scan_row( $raise_future['job_id'] )->retain_until && $rl->retain_until === ct_scan_row( $raise_legacy['job_id'] )->retain_until, 'An extended deletion date was shortened when the configuration went back.' );

// Leap days: a period that starts on 29 February ends on 1 March, never on 28 February.
$leap_r2  = (object) array( 'status' => 'failed', 'identity' => str_repeat( 'a', 32 ), 'hold_reason' => null, 'hold_until' => null, 'terms_version' => '2026-10-21-r2', 'terms_accepted_at' => '2024-02-29 12:00:00', 'created_at' => '2024-02-29 12:00:30', 'closed_at' => '2024-03-02 00:00:00', 'retain_until' => '2027-03-01 12:00:00' );
$leap_new = (object) array( 'status' => 'failed', 'identity' => str_repeat( 'a', 32 ), 'hold_reason' => null, 'hold_until' => null, 'terms_version' => '2027-06-01-r3', 'terms_accepted_at' => '2024-02-20 12:00:00', 'created_at' => '2024-02-20 12:00:30', 'closed_at' => '2024-02-29 12:00:00', 'retain_until' => '2030-03-01 12:00:00' );
ct_test_assert( '2027-03-01 12:00:00' === ct_scan_retain_until( $leap_r2 ) && '2027-03-01 12:00:00' === ct_scan_required_retain_until( $leap_r2 ) && '2030-03-01 12:00:00' === ct_scan_retain_until( $leap_new ), 'A period starting on 29 February does not end on 1 March.' );
ct_test_assert( ! ct_scan_deletion_allowed( $leap_r2, '2027-02-28 23:59:59' ) && ct_scan_deletion_allowed( $leap_r2, '2027-03-01 12:00:00' ) && ! ct_scan_deletion_allowed( $leap_new, '2030-02-28 23:59:59' ) && ct_scan_deletion_allowed( $leap_new, '2030-03-01 12:00:00' ), 'A leap-day period allowed deletion early (or never).' );
$leap_r2->retain_until = '2027-02-28 12:00:00';
ct_test_assert( array( 'extend', '2027-03-01 12:00:00' ) === ct_scan_deletion_decision( $leap_r2, '2027-03-05 00:00:00' ), 'A stored 28 February date for a 29 February acceptance was not extended to 1 March.' );

// The PHP and database clocks disagreeing by more than five minutes (either way) stops deletions; logged once.
$skewed = ct_test_aged_job( 'ret-skew.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $skewed );
$log = tempnam( sys_get_temp_dir(), 'ctret' );
$previous_log = ini_set( 'error_log', $log );
$wpdb->query( 'SET @@session.timestamp = ' . ( time() + 600 ) );
ct_test_assert( ! ct_scan_clock_is_sane( ct_scan_utc_now() ), 'A database clock ten minutes ahead of PHP was accepted.' );
ct_test_maintain();
ct_test_maintain();
ct_test_assert( ct_test_exists( $skewed ) && get_post( $skewed['request_id'] ), 'Evidence was deleted while the PHP and database clocks disagreed.' );
$wpdb->query( 'SET @@session.timestamp = ' . ( time() - 600 ) );
ct_test_assert( ! ct_scan_clock_is_sane( ct_scan_utc_now() ), 'A database clock ten minutes behind PHP was accepted.' );
$wpdb->query( 'SET @@session.timestamp = DEFAULT' );
ct_test_assert( ct_scan_clock_is_sane( ct_scan_utc_now() ), 'Agreeing clocks were refused.' );
$clock_logged = substr_count( (string) file_get_contents( $log ), 'retention deletions skipped' );
ct_test_maintain();
ini_set( 'error_log', (string) $previous_log );
@unlink( $log );
ct_test_assert( 1 === $clock_logged, "The clock problem was logged $clock_logged times over two runs instead of once." );
ct_test_assert( ! ct_test_exists( $skewed ) && false === get_option( 'ct_scan_retention_clock_warned' ), 'Deletion did not resume, or the warning was not reset, once the clocks agreed.' );

// A due job whose linked post carries another record's identity is kept whole (no tombstone, no scrub).
$foreign = ct_test_aged_job( 'ret-foreign.example.net', 'failed', '-3 years -1 day', '-1 day' );
update_post_meta( $foreign['request_id'], '_ct_scan_identity', str_repeat( 'b', 32 ) );
ct_test_maintain();
$fr = ct_scan_row( $foreign['job_id'] );
ct_test_assert( $fr && get_post( $foreign['request_id'] ) && 'fixture@example.com' === $fr->contact_email && null === $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $foreign['job_id'] ) ), 'A job was (partly) deleted although its linked post belongs to another record.' );
// A restored job row whose request id now belongs to another post (a recycled id): the row is deleted again, the post is kept.
$recycled = ct_test_aged_job( 'ret-recycled.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $recycled );
$saved = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE job_id = %d", $recycled['job_id'] ), ARRAY_A );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $recycled ) && ! get_post( $recycled['request_id'] ), 'Fixture expected the recycled-id job to be deleted.' );
$saved['retention_checked_at'] = ct_scan_utc_now(); // examined just now: only the tombstone loop reaches it
$wpdb->insert( $jobs, $saved );
wp_insert_post( array( 'import_id' => $recycled['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'another record' ) );
update_post_meta( $recycled['request_id'], '_ct_scan_identity', str_repeat( 'e', 32 ) );
ct_test_assert( ct_test_exists( $recycled ) && get_post( $recycled['request_id'] ), 'Fixture failed to restore the row and recycle the post id.' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $recycled ) && get_post( $recycled['request_id'] ), 'A restored row survived, or its tombstone deleted a post that belongs to another record.' );
wp_delete_post( $recycled['request_id'], true );

// One budget of 50 deletion attempts per run, shared by the evidence step and both tombstone loops.
ct_test_maintain();
$ghost_jobs = array();
$ghost_rows = array();
for ( $i = 0; $i < 10; $i++ ) {
	$g = ct_test_aged_job( "ret-budget-ghost-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
	ct_test_make_due( $g );
	$ghost_rows[] = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE job_id = %d", $g['job_id'] ), ARRAY_A );
	$ghost_jobs[] = $g;
}
ct_test_maintain();
ct_test_assert( 0 === count( array_filter( $ghost_jobs, 'ct_test_exists' ) ), 'Fixture expected the budget ghosts to be deleted.' );
foreach ( $ghost_rows as $g ) {
	$g['retention_checked_at'] = ct_scan_utc_now(); // examined just now: only the tombstone loop reaches these
	$wpdb->insert( $jobs, $g );
}
$budget_jobs = array();
for ( $i = 0; $i < 45; $i++ ) {
	$budget_jobs[] = ct_test_aged_job( "ret-budget-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
	ct_test_make_due( end( $budget_jobs ) );
}
ct_scan_retention_run( true );
$left = count( array_filter( $ghost_jobs, 'ct_test_exists' ) ) + count( array_filter( $budget_jobs, 'ct_test_exists' ) );
ct_test_assert( $left >= 5 && $left < 55, "One run did not keep to a single budget of 50 deletions ($left of 55 remain)." );
for ( $run = 0; $run < 4 && $left > 0; $run++ ) {
	ct_test_maintain();
	$left = count( array_filter( $ghost_jobs, 'ct_test_exists' ) ) + count( array_filter( $budget_jobs, 'ct_test_exists' ) );
}
ct_test_assert( 0 === $left, "Later runs did not finish the remaining deletions ($left remain)." );

// A worker poll that is handed a job does not wait for retention; a poll with nothing to hand out runs it.
$wpdb->update( $jobs, array( 'status' => 'cancelled', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => $live['job_id'] ) ); // the only other queued job here
$claim_due = ct_test_aged_job( 'ret-claim-due.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $claim_due );
list( $claim_request, $claim_fields ) = ct_test_request( 'ret-claim.example.net' );
$request_ids[] = $claim_request;
$claim_event = ct_scan_on_request_ready( $claim_request, $claim_fields );
ct_test_queue_job( $claim_event['job_id'] );
delete_transient( 'ct_scan_retention_last' );
$claimed = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data();
ct_test_assert( is_array( $claimed['job'] ) && ct_test_exists( $claim_due ), 'A claim that handed out a job ran retention first (or no job was handed out).' );
delete_transient( 'ct_scan_retention_last' );
$idle = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data();
ct_test_assert( null === $idle['job'] && ! ct_test_exists( $claim_due ), 'A claim with nothing to hand out did not run retention.' );
ct_test_end_job( (int) $claimed['job']['id'] );
delete_transient( 'ct_scan_retention_last' );

// ---- Target control: a job waiting for (or in the middle of) a control check never closes -----------------------
foreach ( array( 'pending' => null, 'checking' => '+2 minutes' ) as $state => $lease_for ) {
	$ctl = ct_test_aged_job( "ret-control-{$state}.example.net", 'failed', '-3 years -1 day', '-1 day' );
	$wpdb->update( $jobs, array( 'status' => 'awaiting_control', 'control_required' => 1, 'control_state' => $state, 'control_attempts' => 1, 'control_lease_hash' => $lease_for ? str_repeat( 'c', 64 ) : null, 'control_lease_until' => $lease_for ? ct_test_old( $lease_for ) : null, 'authorization_expires_at' => ct_test_old( '+30 days' ), 'finished_at' => null, 'closed_at' => ct_test_old( '-4 years' ), 'retain_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $ctl['job_id'] ) );
	ct_test_maintain();
	$cr = ct_scan_row( $ctl['job_id'] );
	ct_test_assert( $cr && 'awaiting_control' === $cr->status && $state === $cr->control_state && null === $cr->closed_at && null === $cr->retain_until && get_post( $ctl['request_id'] ), "A job awaiting target control ({$state}) was closed or deleted by retention." );
	$wpdb->delete( $jobs, array( 'job_id' => $ctl['job_id'] ) );
}
// A restored row that a tombstone recognises is not deleted while it holds a lease (a control check in progress or a
// running scan): that would free the one-at-a-time gate while its traffic may be in flight. Once the lease ends, it is.
foreach ( array( 'control' => array( 'status' => 'awaiting_control', 'control_required' => 1, 'control_state' => 'checking', 'control_attempts' => 1, 'control_lease_hash' => str_repeat( 'c', 64 ), 'control_lease_until' => ct_test_old( '+2 minutes' ) ), 'scan' => array( 'status' => 'running', 'attempts' => 1, 'lease_hash' => str_repeat( 'b', 64 ), 'lease_until' => ct_test_old( '+2 minutes' ) ) ) as $kind => $leased ) {
	$gone = ct_test_aged_job( "ret-restore-{$kind}.example.net", 'failed', '-3 years -1 day', '-1 day' );
	ct_test_maintain();
	ct_test_assert( ! ct_test_exists( $gone ), 'Fixture expected the job to be deleted first.' );
	$gstone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $gone['job_id'] ) );
	$wpdb->insert( $jobs, array_merge( array( 'job_id' => $gone['job_id'], 'request_id' => $gone['request_id'], 'target_origin' => "https://ret-restore-{$kind}.example.net/", 'scope_hash' => hash( 'sha256', "https://ret-restore-{$kind}.example.net/" ), 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-3 years -1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'restored@example.com', 'contact_name' => 'Restored', 'referrer' => 'direct', 'created_at' => $gstone->created_at ), $leased ) );
	ct_test_maintain();
	ct_test_assert( ct_test_exists( $gone ), "A restored row holding a live {$kind} lease was deleted by its tombstone mid-lease." );
	$wpdb->update( $jobs, 'control' === $kind ? array( 'control_lease_until' => ct_test_old( '-1 minute' ) ) : array( 'lease_until' => ct_test_old( '-1 minute' ) ), array( 'job_id' => $gone['job_id'] ) );
	ct_test_maintain();
	ct_test_assert( ! ct_test_exists( $gone ), "A restored row was not deleted again after its {$kind} lease ended." );
}

// ---- Fifth review: stale release, identity backfill ownership, restored-post paging ----------------------------
wp_set_current_user( 1 );
// A stale "Release hold" form (for hold H1) cannot end a newer hold H2 placed after H1 was released.
$stale = ct_test_aged_job( 'ret-stale-release.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $stale );
ct_test_assert( true === ct_scan_admin_set_hold( $stale['job_id'], 'First hold H1 for dispute number 1357.', 10 ), 'Fixture hold H1 was refused.' );
$h1_identity = ct_scan_hold_identity( ct_scan_row( $stale['job_id'] ) );
ct_test_assert( true === ct_scan_admin_release_hold( $stale['job_id'], $h1_identity ), 'Releasing H1 failed.' );
ct_test_assert( true === ct_scan_admin_set_hold( $stale['job_id'], 'Second hold H2 for litigation number 2468.', 730 ), 'Fixture hold H2 was refused.' );
$h2 = ct_scan_row( $stale['job_id'] );
$replayed = ct_scan_admin_release_hold( $stale['job_id'], $h1_identity );
$h2_now = ct_scan_row( $stale['job_id'] );
ct_test_assert( is_wp_error( $replayed ) && 'hold_changed' === $replayed->get_error_code() && $h2->hold_until === $h2_now->hold_until && $h2->hold_reason === $h2_now->hold_reason && null === $h2_now->hold_released_at && null === $h2_now->hold_released_by, 'A stale release form for an earlier hold released a newer hold.' );
ct_test_maintain();
ct_test_assert( ct_test_exists( $stale ) && get_post( $stale['request_id'] ), 'A due job under a newer hold was deleted after a stale release.' );
ct_test_assert( true === ct_scan_admin_release_hold( $stale['job_id'], ct_scan_hold_identity( $h2_now ) ), 'The current hold could not be released with its own identity.' );
$wpdb->delete( $jobs, array( 'job_id' => $stale['job_id'] ) );

// The identity backfill never adopts or overwrites the identity of a request post that names another job.
$owner = ct_test_aged_job( 'ret-backfill-owner.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_make_due( $owner );
$wpdb->update( $jobs, array( 'identity' => null ), array( 'job_id' => $owner['job_id'] ) );
update_post_meta( $owner['request_id'], '_ct_scan_job_id', 999999998 );
update_post_meta( $owner['request_id'], '_ct_scan_identity', str_repeat( 'c', 32 ) );
ct_test_maintain();
ct_test_assert( null === ct_scan_row( $owner['job_id'] )->identity && str_repeat( 'c', 32 ) === ct_scan_meta_string( $owner['request_id'], '_ct_scan_identity' ) && ct_test_exists( $owner ) && get_post( $owner['request_id'] ), 'The identity backfill adopted, or the job lost records to, a request post that names another job.' );
delete_post_meta( $owner['request_id'], '_ct_scan_identity' );
ct_test_maintain();
ct_test_assert( null === ct_scan_row( $owner['job_id'] )->identity && '' === ct_scan_meta_string( $owner['request_id'], '_ct_scan_identity' ) && ct_test_exists( $owner ), 'The identity backfill wrote an identity onto a request post that names another job.' );
update_post_meta( $owner['request_id'], '_ct_scan_job_id', $owner['job_id'] );
update_post_meta( $owner['request_id'], '_ct_scan_identity', str_repeat( 'c', 32 ) );
ct_test_maintain();
ct_test_assert( str_repeat( 'c', 32 ) === $wpdb->get_var( $wpdb->prepare( 'SELECT identity FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $owner['job_id'] ) ) && ! ct_test_exists( $owner ), 'Once the request named its job, the backfill did not adopt its identity (and allow the due deletion).' );

// Restored request posts whose deletion is refused, or that name another job, never starve an older restored post.
$stone_row = static function ( $job_id, $post_id, $identity ) {
	return array( 'job_id' => $job_id, 'request_id' => $post_id, 'scope_mac' => str_repeat( 'd', 64 ), 'created_at' => ct_test_old( '-2 years' ), 'deleted_at' => ct_test_old( '-1 day' ), 'reason' => 'retention', 'identity' => $identity );
};
$restored_post = static function ( $job_id, $identity ) {
	$id = wp_insert_post( array( 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
	update_post_meta( $id, '_ct_scan_job_id', $job_id );
	update_post_meta( $id, '_ct_scan_identity', $identity );
	return (int) $id;
};
$target_identity = bin2hex( random_bytes( 16 ) );
$target_post     = $restored_post( 887100000, $target_identity );
ct_test_assert( 1 === $wpdb->insert( ct_scan_tombstones_table(), $stone_row( 887100000, $target_post, $target_identity ) ), 'Fixture tombstone insert failed: ' . $wpdb->last_error );
$target_stone = (int) $wpdb->insert_id;
$refused_posts = array();
$foreign_posts = array();
for ( $i = 1; $i <= 55; $i++ ) {
	$identity        = bin2hex( random_bytes( 16 ) );
	$refused_posts[] = $restored_post( 887100000 + $i, $identity );
	ct_test_assert( 1 === $wpdb->insert( ct_scan_tombstones_table(), $stone_row( 887100000 + $i, end( $refused_posts ), $identity ) ), 'Fixture tombstone insert failed: ' . $wpdb->last_error );
	// Same identity as its tombstone, but the post names another job: never a candidate.
	$identity        = bin2hex( random_bytes( 16 ) );
	$foreign_posts[] = $restored_post( 887100100 + $i, $identity );
	update_post_meta( end( $foreign_posts ), '_ct_scan_job_id', 999999997 );
	ct_test_assert( 1 === $wpdb->insert( ct_scan_tombstones_table(), $stone_row( 887100100 + $i, end( $foreign_posts ), $identity ) ), 'Fixture tombstone insert failed: ' . $wpdb->last_error );
}
$refuse = static function ( $check, $post ) use ( $refused_posts ) {
	return in_array( (int) $post->ID, $refused_posts, true ) ? false : $check;
};
add_filter( 'pre_delete_post', $refuse, 10, 2 );
update_option( 'ct_scan_restored_post_cursor', (string) $target_stone, false ); // start just past the older post: it is reached only by wrapping around
ct_scan_apply_tombstones( ct_scan_utc_now() );
ct_scan_apply_tombstones( ct_scan_utc_now() );
remove_filter( 'pre_delete_post', $refuse, 10 );
$refused_left = count( array_filter( $refused_posts, 'get_post' ) );
$foreign_left = count( array_filter( $foreign_posts, 'get_post' ) );
ct_test_assert( ! get_post( $target_post ) && 55 === $refused_left && 55 === $foreign_left, "Refused or foreign restored posts starved an older restored post, or a foreign post was deleted ($refused_left refused, $foreign_left foreign of 55 kept)." );
foreach ( array_merge( $refused_posts, $foreign_posts ) as $id ) {
	wp_delete_post( $id, true );
}
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() . ' WHERE job_id BETWEEN 887100000 AND 887100200' );

// ---- Sixth review: collations, failed queries, a failed deletion under a raised period ---------------------------
// A tombstones table whose collation differs from the post meta's (utf8mb4_unicode_ci post meta beside a
// utf8mb4_unicode_520_ci tombstones table, say) must not make the restored-post comparison fail silently.
$stones_table = ct_scan_tombstones_table();
$column_info  = static function ( $table, $column ) use ( $wpdb ) {
	return $wpdb->get_row( $wpdb->prepare( 'SELECT CHARACTER_SET_NAME AS charset, COLLATION_NAME AS collation FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s', $table, $column ) );
};
$meta_column     = $column_info( $wpdb->postmeta, 'meta_value' );
$identity_column = $column_info( $stones_table, 'identity' );
ct_test_assert( $meta_column && $identity_column && $meta_column->charset && $identity_column->collation, 'Fixture could not read the column collations.' );
$other_collation = null;
foreach ( array( '_general_ci', '_unicode_ci', '_unicode_520_ci' ) as $suffix ) {
	$candidate = $meta_column->charset . $suffix;
	if ( $candidate !== $meta_column->collation && $wpdb->get_var( $wpdb->prepare( 'SELECT COLLATION_NAME FROM information_schema.COLLATIONS WHERE COLLATION_NAME = %s', $candidate ) ) ) {
		$other_collation = $candidate;
		break;
	}
}
ct_test_assert( null !== $other_collation, 'Fixture found no second collation for ' . $meta_column->charset . '.' );
$collated = ct_test_aged_job( 'ret-collation.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $collated ) && ! get_post( $collated['request_id'] ), 'Fixture expected the collation job to be deleted.' );
$collated_stone = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$stones_table} WHERE job_id = %d", $collated['job_id'] ) );
try {
	ct_test_assert( false !== $wpdb->query( "ALTER TABLE {$stones_table} MODIFY identity char(32) CHARACTER SET {$meta_column->charset} COLLATE {$other_collation} NULL" ), 'Fixture could not change the identity collation: ' . $wpdb->last_error );
	// The fixture really reproduces the problem: a plain comparison across the two columns is refused.
	$suppressed = $wpdb->suppress_errors( true );
	$wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->postmeta} m INNER JOIN {$stones_table} t ON m.meta_value = t.identity" );
	$plain_error = $wpdb->last_error;
	$wpdb->suppress_errors( $suppressed );
	ct_test_assert( '' !== $plain_error, "Fixture expected {$meta_column->collation} against {$other_collation} to be an illegal mix of collations." );
	wp_insert_post( array( 'import_id' => $collated['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
	update_post_meta( $collated['request_id'], '_ct_scan_job_id', $collated['job_id'] );
	update_post_meta( $collated['request_id'], '_ct_scan_identity', $collated_stone->identity );
	delete_option( 'ct_scan_retention_query_warned' );
	ct_test_maintain();
	ct_test_assert( ! get_post( $collated['request_id'] ) && empty( $GLOBALS['ct_scan_retention_query_failure'] ) && ! get_option( 'ct_scan_retention_query_warned' ), "A restored request was not deleted again when the tombstones table uses another collation ({$other_collation}) than the post meta ({$meta_column->collation})." );
} finally {
	$wpdb->query( "ALTER TABLE {$stones_table} MODIFY identity char(32) CHARACTER SET {$identity_column->charset} COLLATE {$identity_column->collation} NULL" );
}
ct_test_assert( $identity_column->collation === $column_info( $stones_table, 'identity' )->collation, 'Fixture could not restore the identity collation.' );

// A failed retention query is never read as "nothing to do" or "no live record": the records are kept, the failure
// is logged once, and the next clean run does the work and forgets the warning.
$failing = ct_test_aged_job( 'ret-failing-query.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $failing ), 'Fixture expected the failing-query job to be deleted.' );
$failing_stone = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$stones_table} WHERE job_id = %d", $failing['job_id'] ) );
wp_insert_post( array( 'import_id' => $failing['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $failing['request_id'], '_ct_scan_job_id', $failing['job_id'] );
update_post_meta( $failing['request_id'], '_ct_scan_identity', $failing_stone->identity );
foreach ( array( 'candidates' => "'_ct_scan_identity'", 'live lookup' => ' OR job_id = ' ) as $kind => $marker ) {
	$break_query = static function ( $query ) use ( $marker, $jobs ) {
		$is_target = ' OR job_id = ' === $marker ? 0 === strpos( $query, "SELECT job_id FROM {$jobs} WHERE request_id = " ) : ( false !== strpos( $query, 'INNER JOIN' ) && false !== strpos( $query, $marker ) );
		return $is_target ? $query . ' AND (' : $query; // a syntax error
	};
	delete_option( 'ct_scan_retention_query_warned' );
	add_filter( 'query', $break_query );
	$suppressed = $wpdb->suppress_errors( true );
	ct_test_maintain();
	$wpdb->suppress_errors( $suppressed );
	remove_filter( 'query', $break_query );
	ct_test_assert( get_post( $failing['request_id'] ) && 'tombstone_posts' === get_option( 'ct_scan_retention_query_warned' ), "A failed restored-post query ({$kind}) was treated as no candidates or no live record, or was not logged." );
}
ct_test_maintain();
ct_test_assert( ! get_post( $failing['request_id'] ) && ! get_option( 'ct_scan_retention_query_warned' ), 'After the query recovered, the restored request was not deleted or the warning was not cleared.' );

// A live row whose retention deletion wrote its tombstone and then failed part-way is not deleted by that tombstone
// before the deadline of a retention period raised since (holds aside, the tombstone loop applies the same deadline).
$partial = ct_test_aged_job( 'ret-partial.example.net', 'cancelled', '-6 years -3 days', '-6 years -2 days', '2027-06-01-r3' );
ct_test_make_due( $partial );
$block_partial = static function ( $check, $post ) use ( $partial ) {
	return (int) $partial['request_id'] === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $block_partial, 10, 2 );
ct_test_maintain();
remove_filter( 'pre_delete_post', $block_partial, 10 );
$pr = ct_scan_row( $partial['job_id'] );
ct_test_assert( $pr && get_post( $partial['request_id'] ) && null !== $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$stones_table} WHERE job_id = %d", $partial['job_id'] ) ), 'Fixture expected a deletion that wrote its tombstone and then failed.' );
// Examined just now, so the evidence step leaves it alone: only the tombstone loop decides in the next run.
$wpdb->update( $jobs, array( 'retention_checked_at' => ct_scan_utc_now() ), array( 'job_id' => $partial['job_id'] ) );
$run_raised(); // eight years from closure: not due for almost two years
ct_test_assert( ct_test_exists( $partial ) && get_post( $partial['request_id'] ) && $pr->retain_until === ct_scan_row( $partial['job_id'] )->retain_until, 'A tombstone deleted a live row (whose deletion had failed) before the deadline of a period raised since.' );
// Under the period in force when it was due, the tombstone loop completes the deletion.
ct_test_maintain();
ct_test_assert( ! ct_test_exists( $partial ) && ! get_post( $partial['request_id'] ), 'The tombstone loop did not complete a failed deletion whose deadline has passed.' );

foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() );
echo "Retention checks passed.\n";
