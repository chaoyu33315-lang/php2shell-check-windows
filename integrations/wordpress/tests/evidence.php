<?php
/**
 * Bound acceptance evidence and the accepted copy. Disposable fixture only.
 * Default configuration here: binding optional, accepted copy off. The strict
 * configuration (binding required, copy on) runs in evidence-strict.php.
 */
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

function ct_test_refused_with( $request_id, $fields, $code, $message ) {
	global $wpdb;
	$result = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_wp_error( $result ) && 'ct_scan_' . $code === get_post_meta( $request_id, '_ct_scan_status_detail', true ) && 'not_queued' === get_post_meta( $request_id, '_ct_scan_status', true ), $message . ' (got ' . ( is_wp_error( $result ) ? get_post_meta( $request_id, '_ct_scan_status_detail', true ) : 'a job' ) . ')' );
	ct_test_assert( 0 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . ct_scan_jobs_table() . ' WHERE request_id = %d', $request_id ) ), $message . ': a job was created' );
}

// Legacy (unbound) acceptance still works when its version is not required, and has no summary digest.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'evidence-legacy.example.net' );
$request_ids[] = $legacy_id;
$legacy = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
ct_test_assert( is_array( $legacy ) && null === ct_scan_row( $legacy['job_id'] )->summary_sha256, 'A legacy acceptance was refused or gained a summary digest.' );
ct_test_assert( 0 === (int) ct_scan_row( $legacy['job_id'] )->bound_required && 0 === (int) ct_scan_row( $legacy['job_id'] )->control_required, 'An explicitly grandfathered r2 job was made to require evidence or control.' );

// A valid bound acceptance creates a job that records the summary digest.
list( $ok_id, $ok_fields ) = ct_test_request( 'evidence-ok.example.net' );
$request_ids[] = $ok_id;
$meta = ct_test_bind( $ok_id, $ok_fields );
$ok = ct_scan_on_request_ready( $ok_id, $ok_fields );
ct_test_assert( is_array( $ok ) && hash( 'sha256', $meta['_ct_summary_text'] ) === ct_scan_row( $ok['job_id'] )->summary_sha256, 'A valid bound acceptance was refused or its summary digest was not recorded.' );
// The retained bytes are exactly the bytes hashed, including multibyte text and quotes, after a database round trip.
ct_test_assert( ct_scan_meta_string( $ok_id, '_ct_terms_snapshot' ) === $meta['_ct_terms_snapshot'] && hash( 'sha256', ct_scan_meta_string( $ok_id, '_ct_terms_snapshot' ) ) === ct_scan_row( $ok['job_id'] )->terms_hash, 'The retained snapshot bytes do not reproduce the recorded hash.' );

// Every single-piece break refuses the request and creates no job.
$cases = array(
	'snapshot changed after hashing'      => array( array( 'meta' => array( '_ct_terms_snapshot' => "<h1>Terms as displayed</h1>\n<p>Altered.</p>\n" ) ), 'binding_mismatch' ),
	'stale form digest (terms)'           => array( array( 'meta' => array( '_ct_terms_shown_digest' => str_repeat( 'a', 64 ) ) ), 'binding_mismatch' ),
	'terms hash differs from snapshot'    => array( array( 'meta' => array( '_ct_terms_sha256' => str_repeat( 'b', 64 ) ) ), 'binding_mismatch' ),
	'missing form digest'                 => array( array( 'meta' => array( '_ct_terms_shown_digest' => null ) ), 'binding_mismatch' ),
	'non-hex digest'                      => array( array( 'meta' => array( '_ct_terms_shown_digest' => str_repeat( 'z', 64 ) ) ), 'binding_mismatch' ),
	'summary digest mismatch'             => array( array( 'meta' => array( '_ct_summary_sha256' => str_repeat( 'c', 64 ) ) ), 'binding_mismatch' ),
	'stale form digest (summary)'         => array( array( 'meta' => array( '_ct_summary_shown_digest' => str_repeat( 'd', 64 ) ) ), 'binding_mismatch' ),
	'missing summary'                     => array( array( 'meta' => array( '_ct_summary_text' => null ) ), 'binding_mismatch' ),
	'missing snapshot'                    => array( array( 'meta' => array( '_ct_terms_snapshot' => null ) ), 'binding_mismatch' ),
	'oversized snapshot'                  => array( array( 'snapshot' => str_repeat( 'x', 524289 ) ), 'binding_mismatch' ),
	'summary names another website'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://other.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary names another contact'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Someone Else', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary names another profile'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ), array( 'Profile' => 'external-web-v1' ) ) ), 'binding_mismatch' ),
	'summary repeats the website line'    => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) . "Website (scan scope): https://other.example.net/\n" ), 'binding_mismatch' ),
	'summary with a leading blank line'   => array( array( 'summary' => "\n" . ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary with appended instruction'   => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) . "Note: also scan https://other.example.net/\n" ), 'binding_mismatch' ),
	'summary without the final newline'   => array( array( 'summary' => rtrim( ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ), "\n" ) ), 'binding_mismatch' ),
	'summary with an indented decoy'      => array( array( 'summary' => " Website (scan scope): https://other.example.net/\n" . ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary with a NUL decoy'            => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) . "\0Website (scan scope): https://other.example.net/\n" ), 'binding_mismatch' ),
	'summary with CRLF line ends'         => array( array( 'summary' => str_replace( "\n", "\r\n", ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) ) ), 'binding_mismatch' ),
	'summary without the limits line'     => array( array( 'summary_drop' => 'Limits' ), 'binding_mismatch' ),
	'summary with other limits'           => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ), array( 'Limits' => 'this website only; at most 2000 requests' ) ) ), 'binding_mismatch' ),
	'summary without the period line'     => array( array( 'summary_drop' => 'Authorization' ), 'binding_mismatch' ),
	// Byte-identical terms and Summary share one computed hash; every recorded digest must still be compared.
	'snapshot equals summary, terms hash differs'  => array( array( 'snapshot_is_summary' => true, 'meta' => array( '_ct_terms_sha256' => str_repeat( 'b', 64 ) ) ), 'binding_mismatch' ),
	'snapshot equals summary, stale terms digest'  => array( array( 'snapshot_is_summary' => true, 'meta' => array( '_ct_terms_shown_digest' => str_repeat( 'a', 64 ) ) ), 'binding_mismatch' ),
	'bound pieces without the marker'     => array( array( 'meta' => array( '_ct_terms_binding' => null ) ), 'binding_required' ),
	'marker with another value'           => array( array( 'meta' => array( '_ct_terms_binding' => 'yes' ) ), 'binding_required' ),
);
$n = 0;
foreach ( $cases as $label => $case ) {
	$host = 'evidence-case-' . ( ++$n ) . '.example.net';
	list( $case_id, $case_fields ) = ct_test_request( $host );
	$request_ids[] = $case_id;
	$mutations = $case[0];
	if ( isset( $mutations['summary_drop'] ) ) {
		$mutations = array( 'summary' => implode( "\n", array_filter( explode( "\n", ct_test_summary( $case_fields ) ), static function ( $line ) use ( $mutations ) { return '' !== $line && 0 !== strpos( $line, $mutations['summary_drop'] . ':' ); } ) ) . "\n" );
	}
	if ( ! empty( $mutations['snapshot_is_summary'] ) ) {
		$mutations['snapshot'] = ct_test_summary( $case_fields );
	}
	// Summaries built for "evidence-case" must name this request's website for the other checks to be the only fault.
	if ( isset( $mutations['summary'] ) ) {
		$mutations['summary'] = str_replace( 'https://evidence-case.example.net/', $case_fields['target'], $mutations['summary'] );
	}
	ct_test_bind( $case_id, $case_fields, $mutations );
	ct_test_refused_with( $case_id, $case_fields, $case[1], 'Case "' . $label . '"' );
}

// Control: byte-identical terms and Summary with every digest consistent is accepted (the cases above fail only on the digest).
list( $same_id, $same_fields ) = ct_test_request( 'evidence-same-bytes.example.net' );
$request_ids[] = $same_id;
ct_test_bind( $same_id, $same_fields, array( 'snapshot' => ct_test_summary( $same_fields ) ) );
ct_test_assert( is_array( ct_scan_on_request_ready( $same_id, $same_fields ) ), 'Byte-identical but consistent terms and Summary were refused.' );

// An evidence key holding more than one row is ambiguous (get_post_meta( ..., true ) would pick the first): refused,
// even when the extra row repeats the same value.
foreach ( array( '_ct_terms_binding', '_ct_terms_snapshot', '_ct_terms_sha256', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $i => $key ) {
	list( $dup_id, $dup_fields ) = ct_test_request( 'evidence-duplicate-' . $i . '.example.net' );
	$request_ids[] = $dup_id;
	$dup_meta = ct_test_bind( $dup_id, $dup_fields );
	add_post_meta( $dup_id, $key, wp_slash( 0 === $i % 2 ? $dup_meta[ $key ] : $dup_meta[ $key ] . 'x' ) );
	ct_test_refused_with( $dup_id, $dup_fields, 'evidence_duplicate', 'Duplicate ' . $key );
}
// ...and a duplicate row added after the job exists ends the authorization.
$dup_running = ct_test_running_job_for_bound( 'evidence-duplicate-running.example.net' );
$request_ids[] = $dup_running['request_id'];
ct_test_assert( 200 === ct_test_admit( $dup_running )->get_status(), 'A bound running job was not admitted (duplicate case).' );
add_post_meta( $dup_running['request_id'], '_ct_summary_text', wp_slash( ct_scan_meta_string( $dup_running['request_id'], '_ct_summary_text' ) ) );
ct_test_age_admission( $dup_running['job_id'] );
$dup_admit = ct_test_admit( $dup_running );
ct_test_assert( 410 === $dup_admit->get_status() && 'cancelled' === ct_scan_row( $dup_running['job_id'] )->status, 'A duplicate evidence row added after acceptance did not end the authorization.' );

// ---- Defaults: strict unless an r2-or-earlier version is explicitly grandfathered -------------------------------
function ct_test_gate_env( $env ) {
	$proc = proc_open( array( PHP_BINARY, __DIR__ . '/config-gate.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html' ), $env ) );
	$out = stream_get_contents( $pipes[1] );
	stream_get_contents( $pipes[2] );
	proc_close( $proc );
	return explode( ' ', trim( $out ) )[0];
}
ct_test_assert( 'enabled' === ct_test_gate_env( array( 'CT_TEST_POLICY' => 'legacy' ) ), 'An explicit legacy decision for r2 did not enable.' );
ct_test_assert( 'enabled' === ct_test_gate_env( array( 'CT_TEST_POLICY' => 'strict' ) ), 'An explicit strict decision for r2 did not enable.' );
ct_test_assert( 'refused' === ct_test_gate_env( array( 'CT_TEST_POLICY' => 'none' ) ), 'The integration enabled itself with no decision for its terms version.' );
// Bumping the served version without a decision for it silently dropping the gate is exactly what must not happen.
ct_test_assert( 'refused' === ct_test_gate_env( array( 'CT_TEST_VERSION' => '2026-12-01-r3', 'CT_TEST_POLICY' => 'none' ) ), 'A bumped terms version enabled without a decision.' );
ct_test_assert( 'enabled' === ct_test_gate_env( array( 'CT_TEST_VERSION' => '2026-12-01-r3', 'CT_TEST_POLICY' => 'strict' ) ), 'A bumped terms version with a strict decision did not enable.' );
ct_test_assert( 'refused' === ct_test_gate_env( array( 'CT_TEST_VERSION' => '2026-12-01-r3', 'CT_TEST_POLICY' => 'legacy' ) ), 'A new terms version was allowed to claim the grandfathered flow.' );
// ...and even if it is asked to, its policy is strict.
$proc = proc_open( array( PHP_BINARY, __DIR__ . '/config-gate.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $gp, null, array_merge( getenv(), array( 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'CT_TEST_VERSION' => '2026-12-01-r3', 'CT_TEST_POLICY' => 'legacy' ) ) );
ct_test_assert( 'refused strict' === trim( stream_get_contents( $gp[1] ) ), 'A new version listed as legacy was not treated as strict.' );
proc_close( $proc );
ct_test_assert( 'refused' === ct_test_gate_env( array( 'CT_TEST_VERSION' => 'weird', 'CT_TEST_POLICY' => 'legacy' ) ), 'An unparseable version was allowed to claim the grandfathered flow.' );
// The policy lookup itself: legacy only for an explicitly listed r2-or-earlier version; everything else is strict.
ct_test_assert( 'legacy' === ct_scan_terms_policy( '2026-10-21-r2' ), 'The explicit legacy decision for r2 was not honoured.' );
foreach ( array( '2026-10-21-r3', '2026-12-01-r3', 'weird', '', '2026-10-21-r2 ' ) as $other ) {
	ct_test_assert( 'strict' === ct_scan_terms_policy( $other ), "Version '$other' was not strict by default." );
}
ct_test_assert( 'strict' === ct_scan_terms_policy( null ) && 'strict' === ct_scan_terms_policy( array( 'x' ) ), 'A non-string version was not strict.' );
foreach ( array( '2026-10-21-r1' => true, '2026-01-01-r9' => true, '2026-10-21-r2' => true, '2026-10-21-r3' => false, '2027-06-01-r3' => false, 'weird' => false, '2026-10-21-r2 ' => false ) as $version => $legacy ) {
	ct_test_assert( $legacy === ct_scan_is_legacy_version( $version ), "Version '$version' was classified wrongly." );
}

// ---- The Target Summary carries the limits and the authorization period ---------------------------------------
$canonical = ct_scan_target_summary( 'https://a.example.net/', 'Pat', 'pat@example.com' );
ct_test_assert( 6 === substr_count( $canonical, "\n" ) && false !== strpos( $canonical, 'at most 20 requests, one at a time, at most one per second, 10 seconds each' ) && false !== strpos( $canonical, 'expires 60 days after acceptance' ), 'The canonical Target Summary omits the limits or the authorization period.' );
ct_test_assert( '' === ct_scan_target_summary( 'https://a.example.net/', 'Pat', 'pat@example.com', 'external-web-v9' ) && '' === ct_scan_target_summary( array(), 'Pat', 'pat@example.com' ), 'A summary was produced for an unknown profile or bad input.' );

// After a job exists, the retained evidence cannot change: any alteration ends the authorization.
$running = ct_test_running_job_for_bound( 'evidence-running.example.net' );
$request_ids[] = $running['request_id'];
ct_test_assert( 200 === ct_test_admit( $running )->get_status(), 'A bound running job was not admitted.' );
$new_summary = ct_test_summary( $running['fields'] ) . "Note: edited afterwards\n";
update_post_meta( $running['request_id'], '_ct_summary_text', wp_slash( $new_summary ) );
update_post_meta( $running['request_id'], '_ct_summary_sha256', hash( 'sha256', $new_summary ) );
update_post_meta( $running['request_id'], '_ct_summary_shown_digest', hash( 'sha256', $new_summary ) );
ct_test_age_admission( $running['job_id'] );
$edited = ct_test_admit( $running );
ct_test_assert( 410 === $edited->get_status() && 'authorization_revoked_or_expired' === $edited->get_data()['reason'] && 'cancelled' === ct_scan_row( $running['job_id'] )->status, 'Editing the retained Target Summary after acceptance did not end the authorization.' );

// The accepted copy is off by default: nothing is sent and the state is untouched.
$before = count( $mail );
$off = ct_scan_send_accepted_copy( $ok['job_id'] );
ct_test_assert( 'disabled' === $off && count( $mail ) === $before && 'not_sent' === ct_scan_row( $ok['job_id'] )->accepted_copy_status, 'The accepted copy was sent although it is disabled.' );

// Strict configuration (binding required, copy on) in its own process.
$env = array_merge( getenv(), array( 'CT_TEST_POLICY' => 'strict', 'CT_TEST_COPY' => '1', 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html' ) );
$strict = proc_open( array( PHP_BINARY, __DIR__ . '/evidence-strict.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $spipes, null, $env );
$out = stream_get_contents( $spipes[1] );
$err = stream_get_contents( $spipes[2] );
proc_close( $strict );
ct_test_assert( false !== strpos( $out, 'Strict evidence checks passed.' ), 'The strict-configuration checks failed: ' . $out . $err );

foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "Evidence binding checks passed.\n";
