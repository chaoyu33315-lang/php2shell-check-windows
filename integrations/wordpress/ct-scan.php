<?php
/**
 * Plugin Name: CompleteTech Authorized PHP2Shell Scan Queue
 * Description: Confirmation-gated, one-target PHP2Shell screening queue for Promo Requests.
 * Version: 0.2.0
 *
 * This MU plugin stores authorization and job state locally. It never starts a
 * scanner process. The external worker talks to the signed REST routes below.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'CT_SCAN_DEFAULT_TERMS_VERSION' ) ) {
	define( 'CT_SCAN_DEFAULT_TERMS_VERSION', '2026-10-21-r2' );
}

if ( ! defined( 'CT_SCAN_SCHEMA_VERSION' ) ) {
	// 7: the retention/hold/tombstone columns (introduced as 6) together with `control_admitted`, so an
	// install that already recorded 6 before `control_admitted` existed re-runs the upgrade.
	define( 'CT_SCAN_SCHEMA_VERSION', '7' );
}

/**
 * Execution profiles. A job freezes its profile id at creation, and the limits
 * live here in code rather than in editable configuration, so a later setting
 * cannot broaden an existing authorization. `r2-header-v1` is the current
 * homepage-header screening: robots.txt (at most six hops) plus the homepage
 * (at most six hops, with at most one HTTP-to-HTTPS origin change) is at most
 * 20 requests. Unknown profiles are refused.
 */
function ct_scan_current_profile() {
	return 'r2-header-v1';
}

/** Disclosed limits of the exact-target control check. */
function ct_scan_control_limits() {
	return array(
		'max_attempts'    => 3,
		'min_interval_ms' => 60000,
		'max_bytes'       => 4096,
		'timeout_ms'      => 10000,
		'valid_ms'        => 1000,
		'lease_seconds'   => 120,
		'path'            => '/.well-known/ct-scan-challenge.txt',
		'dns_label'       => '_ct-scan-challenge',
		'dns_prefix'      => 'ct-scan-verify=',
	);
}

function ct_scan_profile_limits( $profile_id ) {
	$profiles = array(
		'r2-header-v1' => array(
			'http_requests'   => 20,
			// At most one request per second for the target, enforced centrally.
			'min_interval_ms' => 1000,
			// Disclosed bounds: an admission may be used for one second, and one
			// admitted request may finish within the ten-second timeout.
			'valid_ms'        => 1000,
			'timeout_ms'      => 10000,
		),
	);
	return is_string( $profile_id ) && isset( $profiles[ $profile_id ] ) ? $profiles[ $profile_id ] : false;
}

/** Load the secret-bearing settings without ever rendering their values. */
function ct_scan_config() {
	static $config = null;
	if ( null !== $config ) {
		return $config;
	}

	$config = array(
		'enabled'                  => false,
		'supported_terms_version'  => CT_SCAN_DEFAULT_TERMS_VERSION,
		'expected_checker_revision'=> '',
		'expected_rules_as_of'     => '2026-10-21',
		'worker_hmac_secret'       => '',
		'authorization_end_at'     => '2026-12-20T23:59:59Z',
		'confirmation_ttl_hours'   => 168,
		'global_daily_limit'       => 20,
		'target_daily_limit'       => 1,
		'job_retention_days'       => 365,
		// Email the verified contact their accepted copy after confirmation (off by default).
		'send_accepted_copy'       => false,
		// An explicit decision for every terms version the integration serves: array( '<version>' => 'strict' | 'legacy' ).
		// `strict` (also what an unlisted version gets) requires bound evidence and proof of control of the
		// exact target. `legacy` grandfathers an r2-or-earlier acceptance flow and is honoured ONLY for those versions.
		// The integration refuses to enable unless supported_terms_version has an entry here.
		'terms_policy'             => array(),
		// The admission guard is advisory to a scanner that ignores it; only enforced network egress
		// (allow the customer's HTTP/HTTPS, deny private/metadata ranges) makes it a boundary. The
		// operator must state, deliberately, that this exists. See docs/WORDPRESS.md "Egress".
		'egress_enforced'          => false,
		// Owner decisions (2026-10-22): findings 12 months; signed authorization evidence 6 years
		// after request closure, except r2 and earlier acceptances, which keep 3 years from acceptance.
		'evidence_retention_years' => 6,
		'legacy_retention_years'   => 3,
		// How long a deletion tombstone is kept: longer than the longest backup rotation (90 days).
		'tombstone_retention_days' => 120,
	);

	$path = defined( 'CT_SCAN_PRIVATE_CONFIG' )
		? CT_SCAN_PRIVATE_CONFIG
		: WP_CONTENT_DIR . '/ct-scan-private/config.php';
	if ( ! is_string( $path ) || ! is_readable( $path ) ) {
		return $config;
	}

	try {
		$loaded = include $path;
	} catch ( Throwable $error ) {
		return $config;
	}
	if ( ! is_array( $loaded ) ) {
		return $config;
	}
	$config = array_merge( $config, $loaded );
	$config['enabled'] = true === $config['enabled']
		&& is_string( $config['worker_hmac_secret'] )
		&& strlen( $config['worker_hmac_secret'] ) >= 32
		&& true === $config['egress_enforced']
		&& ct_scan_policy_declared( $config )
		&& is_string( $config['expected_checker_revision'] )
		&& 1 === preg_match( '/\A[a-f0-9]{40}\z/i', $config['expected_checker_revision'] )
		&& is_string( $config['supported_terms_version'] )
		&& '' !== $config['supported_terms_version'];

	return $config;
}

/**
 * r2 and earlier acceptances (versions `YYYY-MM-DD-rN` up to `2026-10-21-r2`) are the only ones that may be
 * grandfathered. A version that cannot be parsed is NOT legacy.
 */
function ct_scan_is_legacy_version( $version ) {
	if ( ! is_string( $version ) || ! preg_match( '/\A(\d{4}-\d{2}-\d{2})-r(\d{1,3})\z/', $version, $m ) ) {
		return false;
	}
	return $m[1] < '2026-10-21' || ( '2026-10-21' === $m[1] && (int) $m[2] <= 2 );
}

/**
 * The requirement a terms version carries. STRICT is the default for every version: bound evidence (and,
 * where the control gate exists, proof of control of the exact target). `legacy` is honoured only when the
 * operator listed that exact version AND it is an r2-or-earlier version, so a new version can never inherit
 * the grandfathered flow by omission or by configuration.
 */
function ct_scan_terms_policy( $version ) {
	$config = ct_scan_config();
	$policy = is_array( $config['terms_policy'] ) && is_string( $version ) && isset( $config['terms_policy'][ $version ] ) ? $config['terms_policy'][ $version ] : '';
	return ( 'legacy' === $policy && ct_scan_is_legacy_version( $version ) ) ? 'legacy' : 'strict';
}

/** The integration serves one terms version; its policy must be an explicit, valid decision. */
function ct_scan_policy_declared( $config ) {
	$version = $config['supported_terms_version'];
	if ( ! is_string( $version ) || '' === $version || ! is_array( $config['terms_policy'] ) || ! isset( $config['terms_policy'][ $version ] ) ) {
		return false;
	}
	$policy = $config['terms_policy'][ $version ];
	return 'strict' === $policy || ( 'legacy' === $policy && ct_scan_is_legacy_version( $version ) );
}

/**
 * The canonical Target Summary a signer is shown and signs: the exact website, the client, the profile,
 * the limits of that profile and the authorization period. Deterministic from the request fields and the
 * profile's code-defined limits, so the form, the recorder and this plugin render byte-identical text.
 * Returns '' for an unknown profile.
 */
function ct_scan_target_summary( $target, $name, $email, $profile = null ) {
	$profile = null === $profile ? ct_scan_current_profile() : $profile;
	$limits  = ct_scan_profile_limits( $profile );
	if ( ! $limits || ! is_string( $target ) || ! is_string( $name ) || ! is_string( $email ) ) {
		return '';
	}
	return 'Website (scan scope): ' . $target . "\n"
		. 'Client contact: ' . $name . "\n"
		. 'Client email: ' . $email . "\n"
		. 'Profile: ' . $profile . "\n"
		. 'Limits: this website only (HTTP 80 / HTTPS 443); at most ' . (int) $limits['http_requests'] . ' requests, one at a time, at most one per second, ' . (int) ( $limits['timeout_ms'] / 1000 ) . " seconds each\n"
		. "Authorization: expires 60 days after acceptance (never after the published window end), or when the request closes\n";
}

function ct_scan_enabled() {
	$config = ct_scan_config();
	return ! empty( $config['enabled'] );
}

function ct_scan_jobs_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_jobs';
}

function ct_scan_tombstones_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_tombstones';
}

function ct_scan_nonces_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_nonces';
}

/** Create plugin tables once; MU plugins do not receive activation hooks. */
function ct_scan_maybe_install_schema() {
	$previous = get_option( 'ct_scan_schema_version' );
	if ( $previous === CT_SCAN_SCHEMA_VERSION ) {
		return;
	}
	// A failed upgrade must not re-run dbDelta on every public request: back off for five minutes.
	if ( get_transient( 'ct_scan_schema_backoff' ) ) {
		return;
	}
	global $wpdb;
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$charset = $wpdb->get_charset_collate();
	$jobs    = ct_scan_jobs_table();
	$nonces  = ct_scan_nonces_table();
	$sql     = "CREATE TABLE {$jobs} (
		job_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		request_id bigint(20) unsigned NOT NULL,
		target_origin varchar(512) NOT NULL,
		scope_hash char(64) NOT NULL,
		terms_version varchar(64) NOT NULL,
		terms_hash char(64) NOT NULL,
		terms_accepted_at datetime NOT NULL,
		authorization_expires_at datetime NOT NULL,
		contact_email varchar(320) NOT NULL,
		contact_name varchar(190) NOT NULL,
		referrer varchar(128) NOT NULL,
		status varchar(32) NOT NULL,
		created_at datetime NOT NULL,
		confirmation_token_hash char(64) NULL,
		stop_token_hash char(64) NULL,
		confirmation_expires_at datetime NULL,
		confirmation_email_status varchar(16) NOT NULL DEFAULT 'pending',
		confirmed_at datetime NULL,
		lease_hash char(64) NULL,
		lease_until datetime NULL,
		attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
		started_at datetime NULL,
		finished_at datetime NULL,
		outcome varchar(16) NULL,
		error_code varchar(64) NULL,
		checker_revision char(40) NULL,
		result_json longtext NULL,
		receipt_hash char(64) NULL,
		manual_remainder_status varchar(16) NOT NULL DEFAULT 'pending',
		manual_remainder_notes longtext NULL,
		manual_remainder_completed_at datetime NULL,
		report_notification_status varchar(16) NOT NULL DEFAULT 'not_sent',
		report_notification_at datetime NULL,
		report_delivered_at datetime NULL,
		revoked_at datetime NULL,
		profile_id varchar(32) NOT NULL DEFAULT 'r2-header-v1',
		http_admitted smallint(5) unsigned NOT NULL DEFAULT 0,
		last_admit_ms bigint(20) unsigned NULL,
		summary_sha256 char(64) NULL,
		bound_required tinyint(1) unsigned NOT NULL DEFAULT 0,
		accepted_copy_status varchar(16) NOT NULL DEFAULT 'not_sent',
		accepted_copy_at datetime NULL,
		control_required tinyint(1) unsigned NOT NULL DEFAULT 0,
		control_state varchar(12) NOT NULL DEFAULT 'none',
		control_token_hash char(64) NULL,
		control_page_hash char(64) NULL,
		control_requested_method varchar(12) NULL,
		control_attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
		control_last_attempt_ms bigint(20) unsigned NULL,
		control_leased_ms bigint(20) unsigned NULL,
		control_admitted tinyint(1) unsigned NOT NULL DEFAULT 0,
		control_lease_hash char(64) NULL,
		control_lease_until datetime NULL,
		control_method varchar(16) NULL,
		control_verified_at datetime NULL,
		control_valid_until datetime NULL,
		control_evidence text NULL,
		closed_at datetime NULL,
		retain_until datetime NULL,
		hold_reason varchar(190) NULL,
		hold_until datetime NULL,
		hold_set_by bigint(20) unsigned NULL,
		hold_set_at datetime NULL,
		hold_released_by bigint(20) unsigned NULL,
		hold_released_at datetime NULL,
		identity char(32) NULL,
		retention_checked_at datetime NULL,
		PRIMARY KEY  (job_id),
		UNIQUE KEY request_id (request_id),
		KEY status_created (status,created_at),
		KEY scope_created (scope_hash,created_at),
		KEY authorization_expires_at (authorization_expires_at),
		KEY confirmation_token_hash (confirmation_token_hash),
		KEY stop_token_hash (stop_token_hash),
		KEY retain_until (retain_until)
	) {$charset};";
	dbDelta( $sql );
	// Deletion tombstones: identifiers only, no personal data. A restored backup cannot resurrect a
	// deleted record because maintenance deletes anything that matches a tombstone again.
	$tombstones = ct_scan_tombstones_table();
	dbDelta( "CREATE TABLE {$tombstones} (
		tombstone_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		job_id bigint(20) unsigned NOT NULL,
		request_id bigint(20) unsigned NOT NULL,
		scope_mac char(64) NOT NULL,
		created_at datetime NOT NULL,
		deleted_at datetime NOT NULL,
		reason varchar(32) NOT NULL,
		identity char(32) NULL,
		PRIMARY KEY  (tombstone_id),
		UNIQUE KEY identity (job_id,request_id,scope_mac,created_at),
		KEY deleted_at (deleted_at)
	) {$charset};" );
	$sql = "CREATE TABLE {$nonces} (
		nonce_hash char(64) NOT NULL,
		expires_at datetime NOT NULL,
		PRIMARY KEY  (nonce_hash),
		KEY expires_at (expires_at)
	) {$charset};";
	dbDelta( $sql );
	$required = array(
		$jobs   => array( 'job_id', 'request_id', 'target_origin', 'scope_hash', 'terms_version', 'terms_hash', 'terms_accepted_at', 'authorization_expires_at', 'status', 'lease_hash', 'result_json', 'receipt_hash', 'report_delivered_at', 'stop_token_hash', 'profile_id', 'http_admitted', 'last_admit_ms', 'summary_sha256', 'bound_required', 'accepted_copy_status', 'accepted_copy_at', 'control_required', 'control_state', 'control_token_hash', 'control_page_hash', 'control_requested_method', 'control_attempts', 'control_last_attempt_ms', 'control_leased_ms', 'control_admitted', 'control_lease_hash', 'control_lease_until', 'control_method', 'control_verified_at', 'control_valid_until', 'control_evidence', 'closed_at', 'retain_until', 'hold_reason', 'hold_until', 'hold_set_by', 'hold_set_at', 'hold_released_by', 'hold_released_at', 'identity', 'retention_checked_at' ),
		$nonces => array( 'nonce_hash', 'expires_at' ),
		$tombstones => array( 'tombstone_id', 'job_id', 'request_id', 'scope_mac', 'created_at', 'deleted_at', 'reason', 'identity' ),
	);
	foreach ( $required as $table => $columns ) {
		$found = $wpdb->get_col( "SHOW COLUMNS FROM {$table}", 0 );
		if ( ! is_array( $found ) || array_diff( $columns, $found ) ) {
			// Loud once per back-off window, and bounded. The worker API stays refused (fail closed).
			error_log( 'ct-scan: database upgrade to schema ' . CT_SCAN_SCHEMA_VERSION . ' is incomplete for ' . $table . '; the worker API stays refused. Retrying in 5 minutes. Restore from backup or repair the table.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			set_transient( 'ct_scan_schema_backoff', '1', 5 * MINUTE_IN_SECONDS );
			return;
		}
	}
	delete_transient( 'ct_scan_schema_backoff' );
	if ( is_string( $previous ) && '' !== $previous && version_compare( $previous, '3', '<' ) ) {
		// A job that started before request counting existed has no record of what it already
		// sent: it gets no fresh budget, so its remaining admissions are refused.
		$limits = ct_scan_profile_limits( ct_scan_current_profile() );
		$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET http_admitted = %d WHERE status = 'running'", (int) $limits['http_requests'] ) );
	}
	update_option( 'ct_scan_schema_version', CT_SCAN_SCHEMA_VERSION, false );
}
add_action( 'init', 'ct_scan_maybe_install_schema', 2 );

/** Normalize a visitor-supplied URL to the exact authorized HTTP(S) origin. */
function ct_scan_normalize_target( $url ) {
	$bad = function ( $message ) {
		return new WP_Error( 'ct_scan_invalid_target', $message );
	};
	if ( ! is_string( $url ) ) {
		return $bad( 'The website address must be text.' );
	}
	if ( '' === $url || strlen( $url ) > 2048 || preg_match( '/[\x00-\x20\x7f]/', $url ) ) {
		return $bad( 'Enter one valid public website address.' );
	}
	$url = trim( $url );
	$parts = wp_parse_url( $url );
	if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
		return $bad( 'Include a complete http:// or https:// website address.' );
	}
	$scheme = strtolower( $parts['scheme'] );
	$host   = strtolower( $parts['host'] );
	if ( ! in_array( $scheme, array( 'http', 'https' ), true )
		|| isset( $parts['user'] ) || isset( $parts['pass'] )
		|| isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
		return $bad( 'Use an HTTP or HTTPS address without credentials, a query, or a fragment.' );
	}
	$port = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	if ( ( 'https' === $scheme && 443 !== $port ) || ( 'http' === $scheme && 80 !== $port ) ) {
		return $bad( 'Only the standard HTTP and HTTPS ports are allowed.' );
	}
	if ( isset( $parts['path'] ) && '' !== $parts['path'] && '/' !== $parts['path'] ) {
		return $bad( 'Enter the website homepage so the authorized scope is explicit.' );
	}
	if ( false !== strpos( $host, '%' ) || false !== inet_pton( trim( $host, '[]' ) ) ) {
		return $bad( 'IP address literals are not allowed.' );
	}
	if ( preg_match( '/\A(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\z/i', $host ) ) {
		return $bad( 'Numeric IP address forms are not allowed.' );
	}
	if ( strlen( $host ) > 253 || substr( $host, -1 ) === '.' || false !== strpos( $host, '..' ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$labels = explode( '.', $host );
	if ( count( $labels ) < 2 ) {
		return $bad( 'Use a public hostname with at least two labels.' );
	}
	foreach ( $labels as $label ) {
		if ( strlen( $label ) > 63 || ! preg_match( '/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/i', $label ) ) {
			return $bad( 'The website hostname is not valid.' );
		}
	}
	$tld = end( $labels );
	if ( strlen( $tld ) < 2 || ctype_digit( $tld ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$private_suffixes = array( 'localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'test', 'example', 'invalid', 'onion' );
	if ( in_array( $tld, $private_suffixes, true ) || 'localhost' === $host ) {
		return $bad( 'Local and reserved hostnames are not allowed.' );
	}
	return $scheme . '://' . $host . '/';
}

function ct_scan_utc_now() {
	return gmdate( 'Y-m-d H:i:s' );
}

function ct_scan_utc_parse( $value ) {
	if ( ! is_string( $value ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/', $value ) ) {
		return false;
	}
	try {
		$date = new DateTimeImmutable( $value, new DateTimeZone( 'UTC' ) );
		return $date->format( 'Y-m-d\TH:i:s\Z' ) === $value ? $date : false;
	} catch ( Throwable $error ) {
		return false;
	}
}

function ct_scan_meta_string( $post_id, $key ) {
	$value = get_post_meta( $post_id, $key, true );
	return is_string( $value ) ? $value : '';
}

/**
 * Evidence binding. A "bound" acceptance retains the exact terms bytes that the signer was
 * shown and the exact Target Summary, each next to the digest the signer's form carried:
 *
 *   _ct_terms_binding        '1' marks the acceptance as bound
 *   _ct_terms_snapshot       the terms bytes as displayed (the immutable artifact)
 *   _ct_terms_sha256         SHA-256 of those bytes
 *   _ct_terms_shown_digest   the digest the rendered form carried (must equal the above)
 *   _ct_summary_text         the Target Summary as displayed ("Label: value" lines)
 *   _ct_summary_sha256       SHA-256 of that text
 *   _ct_summary_shown_digest the digest the form carried for the summary
 *
 * Any partial or mismatched set refuses the job (and cancels a queued or running one via
 * ct_scan_authorization_is_live). Every version must be bound (the `strict` policy, which is the default)
 * unless the operator grandfathered an r2-or-earlier version as `legacy` in config `terms_policy`.
 */
function ct_scan_check_bound_evidence( $request_id, $terms_hash, $identity, $required, $profile ) {
	// get_post_meta( ..., true ) silently returns the first of several rows, so an evidence key that
	// holds more than one value is ambiguous: refuse rather than pick one.
	foreach ( array( '_ct_terms_binding', '_ct_terms_snapshot', '_ct_terms_sha256', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $key ) {
		if ( count( (array) get_post_meta( $request_id, $key, false ) ) > 1 ) {
			return new WP_Error( 'ct_scan_evidence_duplicate', 'The saved acceptance holds more than one value for a piece of evidence.' );
		}
	}
	$marker  = ct_scan_meta_string( $request_id, '_ct_terms_binding' );
	$partial = false;
	foreach ( array( '_ct_terms_snapshot', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $key ) {
		if ( '' !== ct_scan_meta_string( $request_id, $key ) ) {
			$partial = true;
		}
	}
	if ( '1' !== $marker ) {
		if ( $required || '' !== $marker || $partial ) {
			return new WP_Error( 'ct_scan_binding_required', 'The saved acceptance does not carry the required bound evidence.' );
		}
		return array( 'bound' => false, 'summary_sha256' => null, 'required' => false );
	}
	$snapshot = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary  = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	if ( '' === $snapshot || strlen( $snapshot ) > 524288 || '' === $summary || strlen( $summary ) > 8192 ) {
		return new WP_Error( 'ct_scan_binding_mismatch', 'The retained terms or Target Summary is missing or oversized.' );
	}
	$snapshot_hash = hash( 'sha256', $snapshot );
	$summary_hash  = hash( 'sha256', $summary );
	// A list of [computed, recorded] pairs, never keyed by the computed hash: byte-identical terms and
	// Summary would share a key and silently drop the terms comparison.
	$checks = array(
		array( $snapshot_hash, $terms_hash ),
		array( $snapshot_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_terms_shown_digest' ) ) ),
		array( $summary_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_summary_sha256' ) ) ),
		array( $summary_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_summary_shown_digest' ) ) ),
	);
	foreach ( $checks as $check ) {
		list( $computed, $value ) = $check;
		if ( ! is_string( $value ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $value ) || ! hash_equals( $computed, $value ) ) {
			return new WP_Error( 'ct_scan_binding_mismatch', 'The retained evidence does not match the digest the signer was shown.' );
		}
	}
	// The Target Summary must be exactly the canonical text of the authorized request (website, client,
	// profile, limits, authorization period): nothing before, between or after, so no decoy or appended
	// instruction can ride along, and the limits the signer saw are the limits the job runs under.
	$expected = ct_scan_target_summary( $identity['target'], $identity['name'], $identity['email'], $profile );
	if ( '' === $expected || ! hash_equals( $expected, $summary ) ) {
		return new WP_Error( 'ct_scan_binding_mismatch', 'The retained Target Summary is not the canonical summary of the authorized request.' );
	}
	return array( 'bound' => true, 'summary_sha256' => $summary_hash, 'required' => (bool) $required );
}

/** Check the saved request and acceptance snapshot before any job is created. */
function ct_scan_validate_saved_request( $request_id, $fields, $require_current_terms = true, $frozen_expiry = '', $frozen = null ) {
	// Authorization is judged on what the database holds now, never on an object-cache copy.
	clean_post_cache( (int) $request_id );
	$config = ct_scan_config();
	$post   = get_post( $request_id );
	if ( ! $post || 'ct_promo_request' !== $post->post_type || 'private' !== $post->post_status ) {
		return new WP_Error( 'ct_scan_request_missing', 'The saved private request could not be verified.' );
	}
	if ( ! is_array( $fields ) ) {
		return new WP_Error( 'ct_scan_fields_invalid', 'The saved request fields could not be verified.' );
	}
	foreach ( array( 'target', 'email', 'name', 'referrer' ) as $key ) {
		if ( ! isset( $fields[ $key ] ) || ! is_string( $fields[ $key ] ) ) {
			return new WP_Error( 'ct_scan_fields_incomplete', 'The saved request fields are incomplete.' );
		}
	}
	$target = ct_scan_normalize_target( $fields['target'] );
	if ( is_wp_error( $target ) || $target !== $fields['target'] ) {
		return new WP_Error( 'ct_scan_target_mismatch', 'The saved authorized target is not in normalized form.' );
	}
	$email = sanitize_email( $fields['email'] );
	$name  = sanitize_text_field( $fields['name'] );
	$ref   = sanitize_title( $fields['referrer'] );
	if ( ! is_email( $email ) || $email !== $fields['email'] || '' === $name || $name !== $fields['name']
		|| '' === $ref || $ref !== $fields['referrer'] ) {
		return new WP_Error( 'ct_scan_contact_mismatch', 'The saved contact or referral fields are incomplete.' );
	}
	foreach ( array(
		'_ct_scan_target' => $target,
		'_ct_scan_email'  => $email,
		'_ct_scan_name'   => $name,
		'_ct_ref'         => $ref,
	) as $key => $expected ) {
		if ( ct_scan_meta_string( $request_id, $key ) !== $expected ) {
			return new WP_Error( 'ct_scan_request_readback_mismatch', 'The saved request did not match its authorization event.' );
		}
	}
	if ( '1' !== ct_scan_meta_string( $request_id, '_ct_terms_saved' ) ) {
		return new WP_Error( 'ct_scan_acceptance_incomplete', 'A complete saved terms acceptance is required.' );
	}
	$terms_version = ct_scan_meta_string( $request_id, '_ct_terms_version' );
	$terms_url     = ct_scan_meta_string( $request_id, '_ct_terms_url' );
	$terms_hash    = strtolower( ct_scan_meta_string( $request_id, '_ct_terms_sha256' ) );
	$accepted_raw  = ct_scan_meta_string( $request_id, '_ct_terms_accepted_at' );
	$contract      = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$accepted_at   = ct_scan_utc_parse( $accepted_raw );
	if ( ( $require_current_terms && $terms_version !== $config['supported_terms_version'] ) || '' === $terms_url
		|| ! preg_match( '/\A[a-f0-9]{64}\z/', $terms_hash ) || ! $accepted_at
		|| '' === trim( $contract ) ) {
		return new WP_Error( 'ct_scan_acceptance_stale', 'The saved terms acceptance is missing or no longer current.' );
	}
	if ( $accepted_at->getTimestamp() > time() + 300 ) {
		return new WP_Error( 'ct_scan_acceptance_time_invalid', 'The saved acceptance time could not be verified.' );
	}
	$expected_lines = array(
		'Client contact'       => $name,
		'Client email'         => $email,
		'Website (scan scope)' => $target,
		'Referred by'          => $ref,
	);
	foreach ( $expected_lines as $label => $expected ) {
		if ( ! preg_match( '/^' . preg_quote( $label, '/' ) . ':\s*(.*)$/m', $contract, $match ) || trim( $match[1] ) !== $expected ) {
			return new WP_Error( 'ct_scan_contract_mismatch', 'The saved acceptance copy does not match the authorized request fields.' );
		}
	}
	if ( false === strpos( $post->post_content, $contract ) ) {
		return new WP_Error( 'ct_scan_contract_readback_mismatch', 'The saved acceptance copy could not be read back from the request.' );
	}
	// A job's evidence requirement and profile are frozen when it is created, so a later
	// configuration change can neither relax nor tighten an authorization already given.
	$bound_required = is_array( $frozen ) ? (bool) $frozen['bound_required'] : 'strict' === ct_scan_terms_policy( $terms_version );
	$profile        = is_array( $frozen ) ? (string) $frozen['profile'] : ct_scan_current_profile();
	$bound = ct_scan_check_bound_evidence( $request_id, $terms_hash, array( 'target' => $target, 'email' => $email, 'name' => $name ), $bound_required, $profile );
	if ( is_wp_error( $bound ) ) {
		return $bound;
	}
	if ( $require_current_terms ) {
		$window_end = ct_scan_utc_parse( $config['authorization_end_at'] );
		if ( ! $window_end ) {
			return new WP_Error( 'ct_scan_config_invalid', 'The authorization end date is not configured.' );
		}
		$expires = $accepted_at->modify( '+60 days' );
		if ( $window_end < $expires ) {
			$expires = $window_end;
		}
	} else {
		if ( ! preg_match( '/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\z/', $frozen_expiry ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		try {
			$expires = new DateTimeImmutable( $frozen_expiry, new DateTimeZone( 'UTC' ) );
		} catch ( Throwable $error ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		if ( $expires > $accepted_at->modify( '+60 days' ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry exceeds its accepted window.' );
		}
	}
	if ( $expires <= new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) ) {
		return new WP_Error( 'ct_scan_authorization_expired', 'The scan authorization window has expired.' );
	}
	return array(
		'post'                  => $post,
		'target'                => $target,
		'email'                 => $email,
		'name'                  => $name,
		'referrer'              => $ref,
		'terms_version'         => $terms_version,
		'terms_hash'            => $terms_hash,
		'terms_accepted_at'     => $accepted_at->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'authorization_expires' => $expires->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'summary_sha256'        => $bound['summary_sha256'],
		'bound_required'        => $bound_required,
	);
}

/** Acquire the per-site MySQL advisory lock used to serialize state changes. */
function ct_scan_lock_acquire( $wait_seconds = 0 ) {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	// Worker paths never wait (they fail closed and retry). Customer stop and
	// operator revocation may wait briefly so a concurrent admission cannot make
	// a cancellation spuriously fail.
	$wait = max( 0, min( 5, (int) $wait_seconds ) );
	return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, $wait ) );
}

function ct_scan_lock_release() {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) );
}

function ct_scan_mark_request_status( $request_id, $status, $detail = '' ) {
	update_post_meta( $request_id, '_ct_scan_status', sanitize_key( $status ) );
	if ( '' !== $detail ) {
		update_post_meta( $request_id, '_ct_scan_status_detail', sanitize_key( $detail ) );
	} else {
		delete_post_meta( $request_id, '_ct_scan_status_detail' );
	}
}

function ct_scan_safe_notice( $request_id, $code ) {
	ct_scan_mark_request_status( $request_id, 'not_queued', $code );
	return new WP_Error( 'ct_scan_' . sanitize_key( $code ), 'The request was retained, but the scan was not queued.' );
}

/**
 * Single event entry point. The theme calls this only after durable readback;
 * the plugin repeats that readback and never infers scope from post text.
 */
function ct_scan_on_request_ready( $request_id, $fields ) {
	$request_id = absint( $request_id );
	if ( ! $request_id || ! ct_scan_enabled() ) {
		if ( $request_id ) {
			return ct_scan_safe_notice( $request_id, 'disabled' );
		}
		return new WP_Error( 'ct_scan_request_id_invalid', 'The saved request could not be identified.' );
	}
	$config = ct_scan_config();
	$token  = bin2hex( random_bytes( 32 ) );
	// Separate long-lived token for the customer's Stop link; only its hash is stored.
	$stop_token = bin2hex( random_bytes( 32 ) );
	$now    = time();
	$ttl    = max( 1, min( 168, absint( $config['confirmation_ttl_hours'] ) ) );
	$created = gmdate( 'Y-m-d H:i:s', $now );
	$confirm_expires = gmdate( 'Y-m-d H:i:s', $now + ( $ttl * HOUR_IN_SECONDS ) );
	$jobs = ct_scan_jobs_table();
	global $wpdb;
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_safe_notice( $request_id, 'queue_busy' );
	}
	try {
		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
		if ( $existing ) {
			update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
			update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
			if ( ! empty( $existing->identity ) ) {
				update_post_meta( $request_id, '_ct_scan_identity', $existing->identity );
			}
			update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
			ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
			return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
		}
		if ( get_post_meta( $request_id, '_ct_scan_event_recorded', true ) ) {
			return new WP_Error( 'ct_scan_duplicate_event', 'This request already has a scan event.' );
		}
		$accepted = ct_scan_validate_saved_request( $request_id, $fields );
		if ( is_wp_error( $accepted ) ) {
			return ct_scan_safe_notice( $request_id, $accepted->get_error_code() );
		}
		$scope_hash = hash( 'sha256', $accepted['target'] );
		$since = gmdate( 'Y-m-d H:i:s', $now - DAY_IN_SECONDS );
		$global_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE created_at >= %s", $since ) );
		$target_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE scope_hash = %s AND created_at >= %s", $scope_hash, $since ) );
		if ( $global_count >= min( 1000, max( 1, absint( $config['global_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'global_quota' );
		}
		if ( $target_count >= min( 10, max( 1, absint( $config['target_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'target_quota' );
		}
		$identity = bin2hex( random_bytes( 16 ) );
		$inserted = $wpdb->insert(
			$jobs,
			array(
				'request_id'               => $request_id,
				'target_origin'            => $accepted['target'],
				'scope_hash'               => $scope_hash,
				'terms_version'            => $accepted['terms_version'],
				'terms_hash'               => $accepted['terms_hash'],
				'terms_accepted_at'        => $accepted['terms_accepted_at'],
				'authorization_expires_at' => $accepted['authorization_expires'],
				'contact_email'            => $accepted['email'],
				'contact_name'             => $accepted['name'],
				'referrer'                 => $accepted['referrer'],
				'status'                   => 'awaiting_confirmation',
				'created_at'               => $created,
				'confirmation_token_hash'  => hash( 'sha256', $token ),
				'confirmation_expires_at'  => $confirm_expires,
				'stop_token_hash'          => hash( 'sha256', $stop_token ),
				'profile_id'               => ct_scan_current_profile(),
				'summary_sha256'           => $accepted['summary_sha256'],
				'bound_required'           => $accepted['bound_required'] ? 1 : 0,
				// Opaque identity mirrored on the private request: lets a deletion tombstone recognise
				// the same record after a restore without matching on recyclable numeric ids.
				'identity'                 => $identity,
				// Frozen at creation: a later configuration change cannot relax an existing job. Every version is strict
				// (requires control of the exact target) unless an r2-or-earlier version was explicitly grandfathered.
				// A profile broader than the r2 header screening can never run without target control.
				'control_required'         => ( 'strict' === ct_scan_terms_policy( $accepted['terms_version'] ) || 'r2-header-v1' !== ct_scan_current_profile() ) ? 1 : 0,
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);
		if ( 1 !== $inserted ) {
			$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
			if ( $existing ) {
				update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
				update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
				if ( ! empty( $existing->identity ) ) {
					update_post_meta( $request_id, '_ct_scan_identity', $existing->identity );
				}
				update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
				ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
				return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
			}
			return ct_scan_safe_notice( $request_id, 'queue_write_failed' );
		}
		$job_id = (int) $wpdb->insert_id;
		update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
		update_post_meta( $request_id, '_ct_scan_job_id', $job_id );
		update_post_meta( $request_id, '_ct_scan_identity', $identity );
		update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $accepted['authorization_expires'] );
		ct_scan_mark_request_status( $request_id, 'awaiting_confirmation' );
	} finally {
		ct_scan_lock_release();
	}

	$url = add_query_arg(
		array( 'action' => 'ct_scan_confirm', 'token' => $token ),
		admin_url( 'admin-post.php' )
	);
	$stop_url = add_query_arg(
		array( 'action' => 'ct_scan_stop', 'stop' => $stop_token ),
		admin_url( 'admin-post.php' )
	);
	$subject = 'Confirm your authorized PHP2Shell screening';
	$message = "A request was saved to screen the website you authorized.\n\n"
		. "To confirm and allow one passive check of " . wp_parse_url( $accepted['target'], PHP_URL_HOST ) . ", open this link and press Confirm. Opening the link alone does not authorize a scan:\n\n"
		. $url . "\n\nThis confirmation expires in {$ttl} hours. If you did not submit this request, ignore this message. Mailbox confirmation shows control of this email address; it does not independently prove domain ownership.\n\n"
		. "To stop this screening at any time, open this link and press Stop. Opening the link alone changes nothing:\n\n"
		. $stop_url . "\n";
	$mail_status = 'unknown';
	$pending = $wpdb->update( $jobs, array( 'confirmation_email_status' => 'unknown' ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'pending' ), array( '%s' ), array( '%d', '%s' ) );
	if ( 1 !== $pending ) {
		update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
		return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => 'unknown' );
	}
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
	try {
		$mail_status = wp_mail( $accepted['email'], $subject, $message ) ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$mail_status = 'unknown';
	}
	$wpdb->update( $jobs, array( 'confirmation_email_status' => $mail_status ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', $mail_status );
	return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => $mail_status );
}
add_action( 'ct_promo_request_ready', 'ct_scan_on_request_ready', 10, 2 );

function ct_scan_row( $job_id ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE job_id = %d", absint( $job_id ) ) );
}

/** Does this job require proof of control of the exact target? A missing value counts as required. */
function ct_scan_control_required( $row ) {
	return ! is_object( $row ) || ! isset( $row->control_required ) || ! empty( $row->control_required );
}

function ct_scan_authorization_is_live( $row ) {
	if ( ! is_object( $row ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
		|| strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		return false;
	}
	if ( ct_scan_meta_string( (int) $row->request_id, '_ct_scan_authorization_expires_at' ) !== $row->authorization_expires_at ) {
		return false;
	}
	// A job that required proof of control of the exact target is runnable only while that proof stands.
	if ( ct_scan_control_required( $row ) && in_array( $row->status, array( 'queued', 'leased', 'running' ), true ) ) {
		if ( empty( $row->control_verified_at )
			|| ( ! empty( $row->control_valid_until ) && strtotime( $row->control_valid_until . ' UTC' ) <= time() ) ) {
			return false;
		}
	}
	$fields = array(
		'target'   => $row->target_origin,
		'email'    => $row->contact_email,
		'name'     => $row->contact_name,
		'referrer' => $row->referrer,
	);
	$accepted = ct_scan_validate_saved_request( (int) $row->request_id, $fields, false, $row->authorization_expires_at, array( 'bound_required' => ! empty( $row->bound_required ), 'profile' => (string) $row->profile_id ) );
	if ( is_wp_error( $accepted ) ) {
		return false;
	}
	return hash_equals( $row->scope_hash, hash( 'sha256', $accepted['target'] ) )
		&& hash_equals( $row->terms_hash, $accepted['terms_hash'] )
		&& $row->terms_version === $accepted['terms_version']
		&& $row->terms_accepted_at === $accepted['terms_accepted_at']
		&& $row->authorization_expires_at === $accepted['authorization_expires']
		// The retained Target Summary is part of the authorization: it cannot change afterwards.
		&& ( null === $accepted['summary_sha256']
			? empty( $row->summary_sha256 )
			: ( is_string( $row->summary_sha256 ) && hash_equals( $row->summary_sha256, $accepted['summary_sha256'] ) ) );
}

/** Reconcile bounded leases and apply the published data-retention windows. */
function ct_scan_maintenance_locked() {
	global $wpdb;
	$table = ct_scan_jobs_table();
	$now   = ct_scan_utc_now();
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'authorization_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL, confirmation_token_hash = NULL, control_token_hash = NULL, control_page_hash = NULL, control_lease_hash = NULL, control_lease_until = NULL, control_state = 'none' WHERE status IN ('awaiting_confirmation','awaiting_control','queued','leased','running') AND authorization_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'confirmation_expired', finished_at = %s, confirmation_token_hash = NULL WHERE status = 'awaiting_confirmation' AND confirmation_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET control_state = 'pending', control_lease_hash = NULL, control_lease_until = NULL WHERE status = 'awaiting_control' AND control_state = 'checking' AND control_lease_until <= %s",
		$now
	) );
	// Every check was spent (even if the last result never arrived): the job is blocked, not left waiting.
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'blocked', error_code = 'target_control_failed', finished_at = %s, control_state = 'none', control_token_hash = NULL, control_page_hash = NULL, control_lease_hash = NULL, control_lease_until = NULL WHERE status = 'awaiting_control' AND control_state = 'pending' AND control_attempts >= %d",
		$now,
		ct_scan_control_limits()['max_attempts']
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'queued', lease_hash = NULL, lease_until = NULL WHERE status = 'leased' AND lease_until <= %s AND attempts = 0",
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'failed_unknown', outcome = 'failed', error_code = 'lease_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL WHERE status = 'running' AND lease_until <= %s",
		$now,
		$now
	) );
	$queued = $wpdb->get_results( "SELECT job_id,request_id,target_origin,scope_hash,terms_version,terms_hash,terms_accepted_at,authorization_expires_at,contact_email,contact_name,referrer,revoked_at,report_delivered_at,summary_sha256,bound_required,profile_id,status,control_required,control_verified_at,control_valid_until FROM {$table} WHERE status = 'queued'" );
	foreach ( (array) $queued as $row ) {
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => $now, 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		}
	}
	$nonce_table = ct_scan_nonces_table();
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$nonce_table} WHERE expires_at < %s", gmdate( 'Y-m-d H:i:s', time() - 600 ) ) );

}

/** Statuses from which a job never runs again; reaching one is the request's closure. */
function ct_scan_terminal_statuses() {
	return array( 'completed', 'failed', 'failed_unknown', 'cancelled', 'expired', 'blocked' );
}

/** Does this job hold a lease for target traffic: a leased or running scan, or a control check being made? */
function ct_scan_job_holds_lease( $row ) {
	return in_array( $row->status, array( 'leased', 'running' ), true )
		|| ( 'awaiting_control' === $row->status && 'checking' === $row->control_state );
}

function ct_scan_terminal_sql() {
	return "'" . implode( "','", ct_scan_terminal_statuses() ) . "'";
}

/**
 * A stored UTC datetime we are willing to compute a deletion date from: the exact `Y-m-d H:i:s`
 * shape, a real calendar date, and not earlier than 2020 (zero dates, which PHP silently parses
 * into year -1, and other restore/migration debris are refused rather than guessed at).
 */
function ct_scan_valid_datetime( $value ) {
	if ( ! is_string( $value ) || ! preg_match( '/\A(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\z/', $value, $m ) || (int) $m[1] < 2020 || (int) $m[1] > 2200 ) {
		return false;
	}
	if ( ! checkdate( (int) $m[2], (int) $m[3], (int) $m[1] ) || (int) $m[4] > 23 || (int) $m[5] > 59 || (int) $m[6] > 59 ) {
		return false;
	}
	return true;
}

/** The longest retention period honoured, so every derived date stays a valid (pre-2200) date. */
function ct_scan_max_retention_years() {
	return 100;
}

/**
 * A retention period in whole years, never below its floor: 3 for r2-and-earlier acceptances, 6 for
 * everything else. A value that is not a plain positive number (a word, null, a boolean, an array, 0,
 * negative) means "the floor", never "shorter", and fractions round down but never below the floor.
 * A value above ct_scan_max_retention_years() (which would push the deletion date past 2200, where no
 * date is trusted and the record would be kept forever) is clamped to that maximum and logged once.
 */
function ct_scan_clamp_years( $years, $floor = 3 ) {
	static $warned = false;
	$floor = max( 3, (int) $floor );
	if ( ( ! is_int( $years ) && ! is_float( $years ) && ! ( is_string( $years ) && is_numeric( $years ) ) ) || ! is_finite( (float) $years ) ) {
		return $floor;
	}
	if ( (float) $years > ct_scan_max_retention_years() ) {
		if ( ! $warned ) {
			$warned = true;
			error_log( 'ct-scan: a configured retention period above ' . ct_scan_max_retention_years() . ' years was clamped to ' . ct_scan_max_retention_years() . ' years.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
		return max( $floor, ct_scan_max_retention_years() );
	}
	return max( $floor, (int) $years );
}


/**
 * When the signed authorization evidence of a job may be deleted: r2 and earlier acceptances three
 * years from acceptance; every other version six years after the request's closure (owner decision,
 * 2026-10-22). Returns false, and the job is then never deleted, if the base date is not trustworthy.
 * Month/year arithmetic that overflows (Feb 29) lands later, never earlier.
 */
function ct_scan_retain_until( $row ) {
	$config = ct_scan_config();
	if ( ct_scan_is_legacy_version( $row->terms_version ) ) {
		$years = ct_scan_clamp_years( $config['legacy_retention_years'], 3 );
		$base  = $row->terms_accepted_at;
	} else {
		$years = ct_scan_clamp_years( $config['evidence_retention_years'], 6 );
		$base  = $row->closed_at;
	}
	if ( ! ct_scan_valid_datetime( $base ) ) {
		return false;
	}
	try {
		return ( new DateTimeImmutable( $base, new DateTimeZone( 'UTC' ) ) )->modify( '+' . $years . ' years' )->format( 'Y-m-d H:i:s' );
	} catch ( Throwable $error ) {
		return false;
	}
}

/** The grace period after a hold expires before its job becomes deletable (nothing vanishes the minute a hold lapses). */
function ct_scan_hold_grace_days() {
	return 3;
}

/**
 * Is this job under a preservation hold? An unexpired hold preserves, and so does one that expired
 * less than the grace period ago; a hold with a purpose but no expiry (not creatable through the admin
 * action) also preserves, so a damaged hold never causes a deletion.
 */
function ct_scan_job_on_hold( $row, $now ) {
	if ( empty( $row->hold_reason ) ) {
		return false;
	}
	if ( empty( $row->hold_until ) || ! ct_scan_valid_datetime( $row->hold_until ) ) {
		return true;
	}
	$grace_end = ( new DateTimeImmutable( $row->hold_until, new DateTimeZone( 'UTC' ) ) )->modify( '+' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	return $grace_end > $now;
}

/**
 * The earliest date this job's evidence may be deleted, judged from the row today: the period derived from
 * the row under today's configuration (so a longer period configured after closure is honoured), and never
 * less than three years after the record's creation. False if a base date cannot be trusted.
 *
 * A record is created within moments of the acceptance it records, so a derived date within a day of
 * "creation + 3 years" is accepted as it is. A derived date more than a day short of that (in practice: an
 * r2-or-earlier acceptance dated more than a day before its record was created, the stated acceptance date
 * and the plugin's own creation stamp disagreeing) is replaced by three full years from creation. That date
 * is later than the promised three years from acceptance, and it is a definite date rather than "never".
 */
function ct_scan_required_retain_until( $row ) {
	$derived = ct_scan_retain_until( $row );
	if ( false === $derived || ! ct_scan_valid_datetime( $row->created_at ) ) {
		return false;
	}
	try {
		$created = new DateTimeImmutable( $row->created_at, new DateTimeZone( 'UTC' ) );
		if ( $derived >= $created->modify( '+3 years -1 day' )->format( 'Y-m-d H:i:s' ) ) {
			return $derived;
		}
		return max( $derived, $created->modify( '+3 years' )->format( 'Y-m-d H:i:s' ) );
	} catch ( Throwable $error ) {
		return false;
	}
}

/**
 * What retention may do with this job now: array( 'keep' | 'extend' | 'delete', $date ). Every date involved
 * must be trustworthy, the job terminal and not held, or it is kept. A stored deletion date earlier than the
 * one required today (ct_scan_required_retain_until()) is never honoured: it is EXTENDED to the required date
 * ($date), and the job is deleted only when that later date arrives. A stored date is never shortened.
 */
function ct_scan_deletion_decision( $row, $now ) {
	if ( ! in_array( $row->status, ct_scan_terminal_statuses(), true ) || ct_scan_job_on_hold( $row, $now ) ) {
		return array( 'keep', null );
	}
	// A job without its opaque identity (not yet reached by the identity backfill) is kept until it has one:
	// deleting it would leave a tombstone that cannot recognise its restored request.
	if ( ! isset( $row->identity ) || ! is_string( $row->identity ) || '' === $row->identity ) {
		return array( 'keep', null );
	}
	foreach ( array( $row->created_at, $row->closed_at, $row->retain_until ) as $date ) {
		if ( ! ct_scan_valid_datetime( $date ) ) {
			return array( 'keep', null );
		}
	}
	// A record cannot have closed before it was created; if it appears to, a date is wrong.
	if ( $row->closed_at < $row->created_at ) {
		return array( 'keep', null );
	}
	$required = ct_scan_required_retain_until( $row );
	if ( false === $required ) {
		return array( 'keep', null );
	}
	if ( $row->retain_until < $required ) {
		return array( 'extend', $required );
	}
	return array( $row->retain_until <= $now ? 'delete' : 'keep', null );
}

/** May this job's records be deleted now? Only when ct_scan_deletion_decision() says so; anything doubtful is kept. */
function ct_scan_deletion_allowed( $row, $now ) {
	return 'delete' === ct_scan_deletion_decision( $row, $now )[0];
}

/**
 * May the tombstone loop delete this job row (one that a tombstone recognises) now, as far as its retention
 * deadline is concerned? The loop cannot tell a row restored from a backup from a live row whose retention
 * deletion wrote its tombstone and then failed part-way, so it never deletes a row before the deadline that
 * retention itself would apply today: the later of the stored retain_until (never shortened) and the date
 * required under today's configuration (ct_scan_required_retain_until()). A longer period configured after a
 * failed deletion therefore protects that row exactly as it protects any other.
 *
 * When that date cannot be derived (no valid closure for a current-version acceptance, a damaged creation
 * date), the row cannot be such a live row: retention deleted only rows whose dates were all valid, and a
 * failed deletion leaves those dates as they were. The row is then a restored copy from before its closure
 * (or a damaged one) and the tombstone, which records that this record was already deleted, decides.
 */
function ct_scan_tombstone_deadline_passed( $row, $now ) {
	$required = ct_scan_required_retain_until( $row );
	if ( false === $required ) {
		return true;
	}
	$deadline = $required;
	if ( isset( $row->retain_until ) && ct_scan_valid_datetime( $row->retain_until ) && $row->retain_until > $deadline ) {
		$deadline = $row->retain_until;
	}
	return $deadline <= $now;
}

/**
 * Did the query just run fail? Retention never mistakes a failed query for "nothing to do" (or, worse, for
 * "no live record uses this id"): the caller stops that step and keeps the records. Logged once until a
 * retention run completes without a failed query.
 */
function ct_scan_retention_query_failed( $step ) {
	global $wpdb;
	if ( '' === (string) $wpdb->last_error ) {
		return false;
	}
	$GLOBALS['ct_scan_retention_query_failure'] = true;
	if ( ! get_option( 'ct_scan_retention_query_warned' ) ) {
		error_log( 'ct-scan: retention step "' . $step . '" stopped: a database query failed; the records are kept and the step is retried on a later run. Logged once until a run completes without a failed query.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		update_option( 'ct_scan_retention_query_warned', $step, false );
	}
	return true;
}

/**
 * A tombstone must not let anyone who reads it (a backup, a database export) test whether a given website
 * was ever a customer: the scope is stored as a keyed MAC, not as the plain hash of the hostname.
 */
function ct_scan_tombstone_mac( $scope_hash ) {
	return hash_hmac( 'sha256', (string) $scope_hash, wp_salt( 'secure_auth' ) . '|ct-scan-tombstone-v1' );
}

/** Remember a deleted record by identifier only, so a restored backup cannot bring it back. */
function ct_scan_record_tombstone( $row, $reason ) {
	global $wpdb;
	$result = $wpdb->query( $wpdb->prepare(
		'INSERT IGNORE INTO ' . ct_scan_tombstones_table() . ' (job_id, request_id, scope_mac, created_at, deleted_at, reason, identity) VALUES (%d, %d, %s, %s, %s, %s, %s)',
		(int) $row->job_id,
		(int) $row->request_id,
		ct_scan_tombstone_mac( $row->scope_hash ),
		$row->created_at,
		ct_scan_utc_now(),
		substr( sanitize_key( $reason ), 0, 32 ),
		is_string( $row->identity ) ? $row->identity : ''
	) );
	return false !== $result;
}

/**
 * Delete one job and its linked request, whatever status that post is in. True only if the job row is gone
 * and a tombstone exists.
 *
 * The request post is deleted only when it provably belongs to this job (post ids can be recycled after a
 * restore). For a retention deletion, a post that does not carry exactly the job's (non-empty) opaque
 * identity keeps everything (nothing is deleted; retried later). For a restored job row recognised by its tombstone
 * ($tombstone_identity given), the post is deleted only if it carries exactly that identity; otherwise the
 * post is another record and is left alone while the restored row itself is deleted again.
 */
function ct_scan_delete_job_records( $row, $reason, $tombstone_identity = null ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	clean_post_cache( (int) $row->request_id );
	$post = get_post( (int) $row->request_id );
	$ours = $post && 'ct_promo_request' === $post->post_type && (int) $post->ID === (int) $row->request_id;
	if ( $ours ) {
		$post_identity = ct_scan_meta_string( (int) $post->ID, '_ct_scan_identity' );
		if ( null !== $tombstone_identity ) {
			$ours = is_string( $tombstone_identity ) && '' !== $tombstone_identity && hash_equals( $tombstone_identity, $post_identity );
		} elseif ( ! is_string( $row->identity ) || '' === $row->identity || ! hash_equals( $row->identity, $post_identity ) ) {
			// Only an exact, non-empty identity match proves the post is this job's (an empty or different
			// identity may be a recycled id): keep everything and retry later.
			return false;
		}
	}
	if ( ! ct_scan_record_tombstone( $row, $reason ) ) {
		return false;
	}
	// Scrub personal fields first so a failure part-way never leaves contact data behind a deleted link.
	$personal_scrubbed = $wpdb->update( $table, array( 'contact_email' => '', 'contact_name' => '' ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s' ), array( '%d' ) );
	if ( false === $personal_scrubbed ) {
		return false;
	}
	if ( 0 === $personal_scrubbed ) {
		$scrubbed = $wpdb->get_row( $wpdb->prepare( "SELECT contact_email,contact_name FROM {$table} WHERE job_id = %d", (int) $row->job_id ) );
		if ( ! $scrubbed || '' !== $scrubbed->contact_email || '' !== $scrubbed->contact_name ) {
			return false;
		}
	}
	// The request carries the contact details and the full contract copy: delete it in any status
	// (a trashed or re-published copy must not outlive the job that pointed to it).
	if ( $ours ) {
		if ( ! wp_delete_post( (int) $row->request_id, true ) ) {
			return false;
		}
	}
	return false !== $wpdb->delete( $table, array( 'job_id' => (int) $row->job_id ), array( '%d' ) );
}

/**
 * Retention is NOT done under the queue lock. Only one retention run at a time (its own advisory lock);
 * the non-destructive steps are single statements; every deletion takes the queue lock for that one job
 * only (no waiting: a busy queue means "try again next run"), re-reads the row under it and re-checks
 * every condition, so Stop, claims and admissions are never delayed for more than one job's deletion
 * and a hold placed a moment ago is honoured.
 */
function ct_scan_retention_lock_name() {
	global $wpdb;
	return 'ctscanret_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 22 );
}

function ct_scan_retention_lock_acquire() {
	global $wpdb;
	return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', ct_scan_retention_lock_name() ) );
}

function ct_scan_retention_lock_release() {
	global $wpdb;
	$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', ct_scan_retention_lock_name() ) );
}

/** Run retention now (`$force`) or at most about once a minute. Returns true if a run happened. */
function ct_scan_retention_run( $force = false ) {
	if ( ! $force && get_transient( 'ct_scan_retention_last' ) ) {
		return false;
	}
	if ( ! ct_scan_retention_lock_acquire() ) {
		return false;
	}
	try {
		set_transient( 'ct_scan_retention_last', '1', 55 );
		ct_scan_retention_steps( ct_scan_utc_now() );
	} finally {
		ct_scan_retention_lock_release();
	}
	return true;
}

/** Retention from a request path (worker poll, admin page): a failure keeps the records and is logged, never propagated. */
function ct_scan_retention_run_safely() {
	try {
		return ct_scan_retention_run();
	} catch ( Throwable $error ) {
		error_log( 'ct-scan: a retention run failed (' . get_class( $error ) . '); records are kept and the run is retried later.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		return false;
	}
}

/** At most this many deletion attempts per retention run, shared by every deleting step. */
function ct_scan_retention_batch_limit() {
	return 50;
}

/** The largest disagreement tolerated between the PHP clock and the database clock before deletions stop. */
function ct_scan_clock_skew_limit_seconds() {
	return 300;
}

/**
 * Deletion is refused when the server clock looks wrong: if the PHP clock and the database clock disagree
 * by more than five minutes (one of them jumped, forwards or backwards), or if any job carries a (plausible)
 * timestamp later than "now" (a clock that jumped backwards, a bad restore). A forward jump of both clocks
 * together cannot be detected here.
 */
function ct_scan_clock_is_sane( $now ) {
	global $wpdb;
	$db_now = $wpdb->get_var( 'SELECT UTC_TIMESTAMP()' );
	if ( ! is_string( $db_now ) || ! ct_scan_valid_datetime( $db_now ) || abs( strtotime( $db_now . ' UTC' ) - time() ) > ct_scan_clock_skew_limit_seconds() ) {
		return false;
	}
	$table  = ct_scan_jobs_table();
	$limit  = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '+5 minutes' )->format( 'Y-m-d H:i:s' );
	foreach ( array( 'created_at', 'finished_at', 'closed_at', 'terms_accepted_at' ) as $column ) {
		$newest = $wpdb->get_var( "SELECT MAX({$column}) FROM {$table} WHERE {$column} < '2200-01-01 00:00:00'" );
		if ( ct_scan_retention_query_failed( 'clock' ) || ( is_string( $newest ) && $newest > $limit ) ) {
			return false;
		}
	}
	return $now >= '2020-01-01 00:00:00' && $now < '2200-01-01 00:00:00';
}

/** Log a clock that stops deletions once per occurrence (not on every run); forget it once the clock is sane again. */
function ct_scan_note_clock_state( $sane ) {
	$flag = 'ct_scan_retention_clock_warned';
	if ( ! $sane && ! get_option( $flag ) ) {
		error_log( 'ct-scan: retention deletions skipped: the server clock disagrees with the database clock or is earlier than a stored job timestamp. Logged once until the clock is consistent again.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		update_option( $flag, ct_scan_utc_now(), false );
	} elseif ( $sane && get_option( $flag ) ) {
		delete_option( $flag );
	}
}

/**
 * Act on one job if, under the queue lock and from a fresh read, retention may: delete it, or extend a
 * stored deletion date that is earlier than the one required today (compare-and-set, never shorter).
 * Returns 'deleted'|'extended'|'kept'|'failed'|'busy'.
 */
function ct_scan_delete_if_due( $job_id, $now ) {
	global $wpdb;
	if ( ! ct_scan_lock_acquire() ) {
		return 'busy';
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return 'kept';
		}
		list( $action, $until ) = ct_scan_deletion_decision( $row, $now );
		if ( 'extend' === $action ) {
			$updated = $wpdb->update( ct_scan_jobs_table(), array( 'retain_until' => $until, 'retention_checked_at' => null ), array( 'job_id' => (int) $row->job_id, 'retain_until' => $row->retain_until ), array( '%s', '%s' ), array( '%d', '%s' ) );
			return 1 === $updated ? 'extended' : 'kept';
		}
		if ( 'delete' !== $action ) {
			return 'kept';
		}
		return ct_scan_delete_job_records( $row, 'retention' ) ? 'deleted' : 'failed';
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_retention_steps( $now ) {
	global $wpdb;
	$table    = ct_scan_jobs_table();
	$terminal = ct_scan_terminal_sql();
	$deadline = microtime( true ) + 3.0;
	$GLOBALS['ct_scan_retention_query_failure'] = false;
	// 0. A job that can run again is not closed: forget any closure stamped on it. (Clears dates only: keeps data.)
	// If this fails, nothing below may run: a job that can run again could still carry an old deletion date.
	$wpdb->query( "UPDATE {$table} SET closed_at = NULL, retain_until = NULL WHERE status NOT IN ({$terminal}) AND (closed_at IS NOT NULL OR retain_until IS NOT NULL)" );
	if ( ct_scan_retention_query_failed( 'reopen' ) ) {
		return;
	}
	// Everything below stamps "now" or deletes. Refuse all of it if the clock cannot be trusted, so a wrong
	// clock's "now" is never stamped as a closure, a deletion date or an examination time.
	$sane = ct_scan_clock_is_sane( $now );
	ct_scan_note_clock_state( $sane );
	if ( ! $sane ) {
		return;
	}
	// 1. Closure is explicit: the first time a job is seen terminal it is stamped.
	$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET closed_at = COALESCE(finished_at, %s) WHERE closed_at IS NULL AND status IN ({$terminal})", $now ) );
	ct_scan_retention_query_failed( 'closure' ); // only stamps dates; the steps below re-read what they act on
	// A row judged doubtful is re-examined at most daily, so doubtful rows can never starve the rest.
	$recheck = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-1 day' )->format( 'Y-m-d H:i:s' );
	// 1b. Jobs that predate the opaque identity get one (and so does their request) so a restored request
	// can be recognised after deletion. The request's identity is adopted or written only when that post
	// provably belongs to this job (its _ct_scan_job_id is this job's id); a request post that names another
	// job (a recycled id) is left alone, and so is the job, which then stays without identity and is kept.
	// Paged from a stored cursor (wrapping around) so such rows can never starve later ones.
	$identity_cursor = max( 0, (int) get_option( 'ct_scan_identity_cursor', 0 ) );
	$anonymous       = $wpdb->get_results( $wpdb->prepare( "SELECT job_id,request_id,identity FROM {$table} WHERE (identity IS NULL OR identity = '') AND job_id > %d ORDER BY job_id ASC LIMIT 100", $identity_cursor ) );
	$anonymous_failed = ct_scan_retention_query_failed( 'identity' );
	foreach ( $anonymous_failed ? array() : (array) $anonymous as $row ) {
		$identity_cursor = (int) $row->job_id;
		clean_post_cache( (int) $row->request_id );
		$post = get_post( (int) $row->request_id );
		if ( $post && 'ct_promo_request' === $post->post_type ) {
			if ( (string) (int) $row->job_id !== ct_scan_meta_string( (int) $row->request_id, '_ct_scan_job_id' ) ) {
				continue; // The post names another job (or none): touch neither; the job is kept.
			}
			// Adopt an identity the request already carries; otherwise mint one for both.
			$carried  = ct_scan_meta_string( (int) $row->request_id, '_ct_scan_identity' );
			$identity = 1 === preg_match( '/\A[a-f0-9]{32}\z/', $carried ) ? $carried : bin2hex( random_bytes( 16 ) );
			if ( 1 === $wpdb->update( $table, array( 'identity' => $identity ), array( 'job_id' => (int) $row->job_id, 'identity' => $row->identity ), array( '%s' ), array( '%d', '%s' ) ) && $identity !== $carried ) {
				update_post_meta( (int) $row->request_id, '_ct_scan_identity', $identity );
			}
		} else {
			// No request post of ours under that id: the job gets an identity of its own; no post is touched
			// (ct_scan_delete_job_records() never deletes a post that is not this job's request).
			$wpdb->update( $table, array( 'identity' => bin2hex( random_bytes( 16 ) ) ), array( 'job_id' => (int) $row->job_id, 'identity' => $row->identity ), array( '%s' ), array( '%d', '%s' ) );
		}
	}
	if ( ! $anonymous_failed ) {
		update_option( 'ct_scan_identity_cursor', count( (array) $anonymous ) < 100 ? '0' : (string) $identity_cursor, false );
	}
	// 2. The evidence deletion date is set at closure; later it may only be extended (step 4), never shortened.
	// An untrustworthy base leaves it NULL (kept).
	$unset = $wpdb->get_results( $wpdb->prepare( "SELECT job_id,terms_version,terms_accepted_at,closed_at FROM {$table} WHERE closed_at IS NOT NULL AND retain_until IS NULL AND (retention_checked_at IS NULL OR retention_checked_at < %s) ORDER BY job_id ASC LIMIT 200", $recheck ) );
	foreach ( ct_scan_retention_query_failed( 'retain_until' ) ? array() : (array) $unset as $row ) {
		$when = ct_scan_retain_until( $row );
		if ( false !== $when ) {
			$wpdb->update( $table, array( 'retain_until' => $when ), array( 'job_id' => (int) $row->job_id, 'retain_until' => null ), array( '%s' ), array( '%d', '%s' ) );
		} else {
			$wpdb->update( $table, array( 'retention_checked_at' => $now ), array( 'job_id' => (int) $row->job_id ), array( '%s' ), array( '%d' ) );
		}
	}
	// 3. Findings: twelve months after closure (366 days, so a leap day cannot make it early), unless held.
	$findings_cutoff = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-366 days' )->format( 'Y-m-d H:i:s' );
	$grace_edge      = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET result_json = NULL, manual_remainder_notes = NULL WHERE (result_json IS NOT NULL OR manual_remainder_notes IS NOT NULL) AND closed_at IS NOT NULL AND closed_at >= '2020-01-01 00:00:00' AND closed_at < %s AND (hold_reason IS NULL OR (hold_until >= '2020-01-01 00:00:00' AND hold_until <= %s))",
		$findings_cutoff,
		$grace_edge
	) );
	ct_scan_retention_query_failed( 'findings' ); // a failure only keeps the findings longer
	// 4. Evidence: delete what has outlived its retain_until (extending a date that is shorter than today's
	// rules require), except under a hold. One budget of deletion attempts for the whole run (steps 4 and 5).
	$deletions_left = ct_scan_retention_batch_limit();
	$due = $wpdb->get_results( $wpdb->prepare(
		"SELECT job_id FROM {$table} WHERE retain_until IS NOT NULL AND retain_until <= %s AND closed_at IS NOT NULL AND status IN ({$terminal}) AND identity IS NOT NULL AND identity <> '' AND (hold_reason IS NULL OR (hold_until >= '2020-01-01 00:00:00' AND hold_until <= %s)) AND (retention_checked_at IS NULL OR retention_checked_at < %s) ORDER BY retain_until ASC LIMIT 50",
		$now,
		$grace_edge,
		$recheck
	) );
	foreach ( ct_scan_retention_query_failed( 'evidence' ) ? array() : (array) $due as $row ) {
		if ( $deletions_left < 1 || microtime( true ) > $deadline ) {
			break; // enough for one run: continue next time
		}
		$outcome = ct_scan_delete_if_due( (int) $row->job_id, $now );
		if ( 'busy' === $outcome ) {
			break; // the queue is in use: continue next time
		}
		if ( 'deleted' === $outcome || 'failed' === $outcome ) {
			--$deletions_left;
		}
		if ( 'kept' === $outcome || 'failed' === $outcome ) {
			// Doubtful or failed: keep it, and look at it again tomorrow rather than on every run.
			$wpdb->update( $table, array( 'retention_checked_at' => $now ), array( 'job_id' => (int) $row->job_id ), array( '%s' ), array( '%d' ) );
		}
	}
	// 5. A restored backup must not resurrect deleted records: delete matches again (same budget).
	ct_scan_apply_tombstones( $now, $deadline, $deletions_left );
	$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . ct_scan_tombstones_table() . ' WHERE deleted_at < %s', ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . max( 90, (int) ct_scan_config()['tombstone_retention_days'] ) . ' days' )->format( 'Y-m-d H:i:s' ) ) );
	ct_scan_retention_query_failed( 'tombstone_expiry' ); // a failure only keeps tombstones longer
	if ( empty( $GLOBALS['ct_scan_retention_query_failure'] ) && get_option( 'ct_scan_retention_query_warned' ) ) {
		delete_option( 'ct_scan_retention_query_warned' );
	}
}

/**
 * Delete again any job row (and linked request) that a deletion tombstone recognises after a restore.
 * A job row matches on its numeric identifiers AND creation time AND scope; its request post is deleted with
 * it only if the post carries the tombstone's opaque identity (a recycled post id is another record). A
 * request post whose job row was not restored matches only on the opaque identity recorded at creation, and
 * only when no job row currently uses that request or job id (recycled auto-increment ids must never reach a
 * live record). Holds are honoured. Every attempt counts against $deletions_left (shared with step 4).
 */
function ct_scan_apply_tombstones( $now, $deadline = null, &$deletions_left = null ) {
	global $wpdb;
	$table    = ct_scan_jobs_table();
	$stones   = ct_scan_tombstones_table();
	$deadline = null === $deadline ? microtime( true ) + 3.0 : $deadline;
	if ( null === $deletions_left ) {
		$deletions_left = ct_scan_retention_batch_limit();
	}
	// Candidates by numeric ids and creation time; the keyed scope MAC is compared in PHP, under the lock.
	// Rows that cannot be acted on now (held or in grace, holding a lease) are excluded in SQL. The rest are
	// paged by key from where the previous run stopped, wrapping around once, so rows that are skipped or
	// whose deletion keeps failing can never starve later restored rows.
	$grace_edge = ( new DateTimeImmutable( $now, new DateTimeZone( 'UTC' ) ) )->modify( '-' . ct_scan_hold_grace_days() . ' days' )->format( 'Y-m-d H:i:s' );
	$cursor     = max( 0, (int) get_option( 'ct_scan_tombstone_cursor', 0 ) );
	$after_job  = $cursor;
	$after_id   = 0;
	$upper      = PHP_INT_MAX;
	$wrapped    = 0 === $cursor;
	$finished   = false;
	// Part of the budget is left for the restored-post loop below, so restored job rows whose deletion keeps
	// failing can never starve it.
	$post_reserve = intdiv( max( 0, (int) $deletions_left ), 5 );
	for ( $page = 0; $page < 40 && ! $finished; $page++ ) {
		$ghosts = $wpdb->get_results( $wpdb->prepare(
			'SELECT j.job_id, t.tombstone_id, t.scope_mac, t.identity FROM ' . $table . ' j INNER JOIN ' . $stones . ' t ON t.job_id = j.job_id AND t.request_id = j.request_id AND t.created_at = j.created_at'
			. ' WHERE (j.job_id > %d OR (j.job_id = %d AND t.tombstone_id > %d)) AND j.job_id <= %d'
			. " AND (j.hold_reason IS NULL OR (j.hold_until >= '2020-01-01 00:00:00' AND j.hold_until <= %s))"
			. " AND j.status NOT IN ('leased','running') AND NOT (j.status = 'awaiting_control' AND COALESCE(j.control_state, '') = 'checking')"
			. ' ORDER BY j.job_id ASC, t.tombstone_id ASC LIMIT 50',
			$after_job,
			$after_job,
			$after_id,
			$upper,
			$grace_edge
		) );
		if ( ct_scan_retention_query_failed( 'tombstone_rows' ) ) {
			break; // never "no candidates": stop here and continue from the stored cursor next run
		}
		if ( empty( $ghosts ) ) {
			if ( $wrapped ) {
				$finished = true;
				break;
			}
			// Reached the end: start again from the beginning, up to where this run started.
			$wrapped   = true;
			$after_job = 0;
			$after_id  = 0;
			$upper     = $cursor;
			continue;
		}
		foreach ( (array) $ghosts as $ghost ) {
			if ( $deletions_left <= $post_reserve ) {
				// This loop's share of the budget is spent: the next run continues from here.
				break 2;
			}
			if ( microtime( true ) > $deadline || ! ct_scan_lock_acquire() ) {
				// Out of time, or the queue is busy: the next run continues from here.
				update_option( 'ct_scan_tombstone_cursor', (string) $after_job, false );
				return;
			}
			$after_job = (int) $ghost->job_id;
			$after_id  = (int) $ghost->tombstone_id;
			try {
				$row = ct_scan_row( (int) $ghost->job_id );
				// A restored row that holds a live lease (a scan, or a control check in progress) is left until the
				// lease ends (bounded; maintenance reclaims it): deleting it would free the one-at-a-time gate while
				// target traffic for it may still be in flight. Re-checked here under the lock.
				// The row is also kept until the retention deadline that applies to it today has passed: a live row
				// whose retention deletion wrote this tombstone and then failed part-way looks exactly like a restored
				// one, and a period raised since must protect it (ct_scan_tombstone_deadline_passed()).
				if ( $row && hash_equals( (string) $ghost->scope_mac, ct_scan_tombstone_mac( $row->scope_hash ) ) && ! ct_scan_job_on_hold( $row, $now ) && ! ct_scan_job_holds_lease( $row ) && ct_scan_tombstone_deadline_passed( $row, $now ) ) {
					--$deletions_left;
					// A failure leaves the row (and is retried next run); it never stops the other candidates.
					ct_scan_delete_job_records( $row, 'restored', (string) $ghost->identity );
				}
			} finally {
				ct_scan_lock_release();
			}
		}
	}
	update_option( 'ct_scan_tombstone_cursor', $finished ? '0' : (string) $after_job, false );
	// A restored request post whose job row was not restored: matched in SQL on the opaque identity
	// (never on recyclable numeric ids alone) AND on the job id the post names, and only where no job row
	// currently uses that request or job id, so a live record can never be reached. Re-checked under the
	// lock before each deletion. Paged by tombstone id from where the previous run stopped, wrapping around
	// once, so posts whose deletion is refused (a filter, the database) can never starve later ones.
	$postmeta     = $wpdb->postmeta;
	$post_cursor  = max( 0, (int) get_option( 'ct_scan_restored_post_cursor', 0 ) );
	$after_stone  = $post_cursor;
	$upper_stone  = PHP_INT_MAX;
	$post_wrapped = 0 === $post_cursor;
	$post_done    = false;
	for ( $page = 0; $page < 40 && ! $post_done; $page++ ) {
		$restored = $wpdb->get_results( $wpdb->prepare(
			'SELECT t.tombstone_id, t.job_id, t.request_id, t.identity FROM ' . $stones . ' t'
			. ' INNER JOIN ' . $wpdb->posts . " p ON p.ID = t.request_id AND p.post_type = 'ct_promo_request'"
			. ' INNER JOIN ' . $postmeta . " m ON m.post_id = t.request_id AND m.meta_key = '_ct_scan_identity' AND CAST(m.meta_value AS BINARY) = CAST(t.identity AS BINARY)"
			. ' INNER JOIN ' . $postmeta . " k ON k.post_id = t.request_id AND k.meta_key = '_ct_scan_job_id' AND CAST(k.meta_value AS BINARY) = CAST(t.job_id AS BINARY)"
			. " WHERE t.identity IS NOT NULL AND t.identity <> '' AND t.tombstone_id > %d AND t.tombstone_id <= %d"
			. ' AND NOT EXISTS (SELECT 1 FROM ' . $table . ' j WHERE j.request_id = t.request_id OR j.job_id = t.job_id)'
			. ' GROUP BY t.tombstone_id, t.job_id, t.request_id, t.identity ORDER BY t.tombstone_id ASC LIMIT 50',
			$after_stone,
			$upper_stone
		) );
		if ( ct_scan_retention_query_failed( 'tombstone_posts' ) ) {
			break; // never "no candidates": stop here and continue from the stored cursor next run
		}
		if ( empty( $restored ) ) {
			if ( $post_wrapped ) {
				$post_done = true;
				break;
			}
			// Reached the end: start again from the beginning, up to where this run started.
			$post_wrapped = true;
			$after_stone  = 0;
			$upper_stone  = $post_cursor;
			continue;
		}
		foreach ( (array) $restored as $stone ) {
			if ( $deletions_left < 1 || microtime( true ) > $deadline || ! ct_scan_lock_acquire() ) {
				// Out of budget or time, or the queue is busy: the next run continues from here.
				update_option( 'ct_scan_restored_post_cursor', (string) $after_stone, false );
				return;
			}
			$after_stone = (int) $stone->tombstone_id;
			try {
				$live = $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$table} WHERE request_id = %d OR job_id = %d LIMIT 1", (int) $stone->request_id, (int) $stone->job_id ) );
				if ( ct_scan_retention_query_failed( 'tombstone_posts' ) ) {
					// A failed lookup is not "no live record": keep the post and stop; the next run retries from here.
					update_option( 'ct_scan_restored_post_cursor', (string) max( 0, $after_stone - 1 ), false );
					return;
				}
				clean_post_cache( (int) $stone->request_id );
				if ( ! $live && hash_equals( (string) $stone->identity, ct_scan_meta_string( (int) $stone->request_id, '_ct_scan_identity' ) ) && (string) $stone->job_id === ct_scan_meta_string( (int) $stone->request_id, '_ct_scan_job_id' ) ) {
					--$deletions_left;
					if ( ! wp_delete_post( (int) $stone->request_id, true ) ) {
						// Refused (a filter or the database): the post is kept and retried on a later pass. This
						// attempt has been counted and the cursor moves on, so one stuck post can neither spin nor
						// block the rest.
						clean_post_cache( (int) $stone->request_id );
					}
				}
			} finally {
				ct_scan_lock_release();
			}
		}
	}
	update_option( 'ct_scan_restored_post_cursor', $post_done ? '0' : (string) $after_stone, false );
}

/**
 * Place a preservation hold. A hold that still protects the job (unexpired, or inside its grace period) and
 * has not been released is never replaced: a second "place hold" (a stale tab, two administrators, a direct
 * POST) is refused with 'hold_active', so it can neither move the expiry earlier nor erase the stated purpose
 * and who set it. To change a standing hold, release it first (the job stays protected through the grace
 * period), then place the new one. A released hold in its grace period may be replaced, but never by a hold
 * that ends earlier. The write is a compare-and-set on the hold values read under the queue lock.
 */
function ct_scan_admin_set_hold( $job_id, $reason, $days ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'hold_forbidden', 'Only an administrator can place a hold.' );
	}
	$reason = is_string( $reason ) ? trim( wp_strip_all_tags( $reason ) ) : '';
	$days   = is_numeric( $days ) ? (int) $days : 0;
	if ( strlen( $reason ) < 20 || strlen( $reason ) > 190 || $days < 1 || $days > 730 ) {
		return new WP_Error( 'hold_invalid', 'State the purpose (20 to 190 characters) and a duration of 1 to 730 days.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row ) {
			return new WP_Error( 'hold_unavailable', 'This job no longer exists.' );
		}
		$now   = ct_scan_utc_now();
		$until = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '+' . $days . ' days' )->format( 'Y-m-d H:i:s' );
		if ( ct_scan_job_on_hold( $row, $now ) && ( empty( $row->hold_released_at ) || ! ct_scan_valid_datetime( $row->hold_until ) || $row->hold_until > $until ) ) {
			return new WP_Error( 'hold_active', 'This job already has a preservation hold; it was not changed. Release it first to place a different one.' );
		}
		$updated = $wpdb->update(
			ct_scan_jobs_table(),
			array( 'hold_reason' => $reason, 'hold_until' => $until, 'hold_set_by' => (int) $user->ID, 'hold_set_at' => $now, 'hold_released_by' => null, 'hold_released_at' => null ),
			array( 'job_id' => (int) $row->job_id, 'hold_reason' => $row->hold_reason, 'hold_until' => $row->hold_until, 'hold_released_at' => $row->hold_released_at ),
			array( '%s', '%s', '%d', '%s', '%d', '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( false === $updated ) {
			return new WP_Error( 'hold_write_failed', 'The hold could not be recorded.' );
		}
		if ( 1 !== $updated ) {
			return new WP_Error( 'hold_changed', 'The hold changed while this request was handled; reload the queue and try again.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

/**
 * The identity of one specific hold (its purpose, expiry, setter and when it was set), carried by the
 * "Release hold" form, so a release can only ever end the hold the administrator was looking at.
 */
function ct_scan_hold_identity( $row ) {
	return hash( 'sha256', implode( "\n", array( 'ct-scan-hold-v1', (string) $row->job_id, (string) $row->hold_reason, (string) $row->hold_until, (string) $row->hold_set_at, (string) $row->hold_set_by ) ) );
}

/**
 * Release the hold identified by $expected_hold (ct_scan_hold_identity() of the hold shown to the
 * administrator). A stale form (the hold was released and a different one placed since, by another
 * administrator or in another tab) is refused with 'hold_changed' and changes nothing. The write is a
 * compare-and-set on the hold's values as read under the queue lock.
 */
function ct_scan_admin_release_hold( $job_id, $expected_hold = '' ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'hold_forbidden', 'Only an administrator can release a hold.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->hold_reason ) || ! empty( $row->hold_released_at ) ) {
			return new WP_Error( 'hold_unavailable', 'This job has no hold to release.' );
		}
		if ( ! is_string( $expected_hold ) || 1 !== preg_match( '/\A[a-f0-9]{64}\z/', $expected_hold ) || ! hash_equals( ct_scan_hold_identity( $row ), $expected_hold ) ) {
			return new WP_Error( 'hold_changed', 'The hold changed since the queue was loaded; it was not released.' );
		}
		// Releasing ends the hold now, it does not erase it: the purpose stays (with who released it and
		// when), and the job keeps the same three-day grace as a hold that expires. A hold that already
		// expired keeps its own (earlier) end, so a release never lengthens it.
		$now     = ct_scan_utc_now();
		$until   = ( ct_scan_valid_datetime( $row->hold_until ) && $row->hold_until < $now ) ? $row->hold_until : $now;
		$updated = $wpdb->update(
			ct_scan_jobs_table(),
			array( 'hold_until' => $until, 'hold_released_by' => (int) $user->ID, 'hold_released_at' => $now ),
			array( 'job_id' => (int) $row->job_id, 'hold_reason' => $row->hold_reason, 'hold_until' => $row->hold_until, 'hold_set_at' => $row->hold_set_at, 'hold_set_by' => $row->hold_set_by, 'hold_released_at' => null ),
			array( '%s', '%d', '%s' ),
			array( '%d', '%s', '%s', '%s', '%d', '%s' )
		);
		if ( false === $updated ) {
			return new WP_Error( 'hold_write_failed', 'The hold could not be released.' );
		}
		if ( 1 !== $updated ) {
			return new WP_Error( 'hold_changed', 'The hold changed since the queue was loaded; it was not released.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_maintain() {
	if ( ! ct_scan_lock_acquire() ) {
		return false;
	}
	try {
		ct_scan_maintenance_locked();
	} finally {
		ct_scan_lock_release();
	}
	// Retention runs after the queue lock is released (see ct_scan_retention_run()); a failure there never
	// breaks the admin page.
	ct_scan_retention_run_safely();
	return true;
}

function ct_scan_confirmation_token_from_request( $source ) {
	if ( ! isset( $source['token'] ) || ! is_string( $source['token'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['token'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_confirmation_markup( $job_id, $token, $nonce, $target, $terms_version, $accepted_at ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	$accepted_label = esc_html( str_replace( ' ', 'T', $accepted_at ) . 'Z (UTC)' );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirm website screening</title><body><main><h1>Confirm your website screening</h1><p>Confirm one passive check of this exact website origin:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>Terms version accepted: <strong>' . esc_html( $terms_version ) . '</strong><br>Acceptance recorded: <strong>' . $accepted_label . '</strong></p><p>Opening this page alone does not authorize a scan. This confirms control of the request email address; it does not independently prove domain ownership.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_confirm"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="token" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Confirm one passive screening</button></form></main></body></html>';
}

function ct_scan_send_confirmation_page( $message, $status = 200, $markup = '' ) {
	nocache_headers();
	status_header( $status );
	header( 'Content-Type: text/html; charset=UTF-8' );
	header( 'Referrer-Policy: no-referrer' );
	header( 'X-Content-Type-Options: nosniff' );
	header( "Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'" );
	if ( '' === $markup ) {
		$markup = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Website screening</title><body><main><h1>Website screening</h1><p>' . esc_html( $message ) . '</p></main></body></html>';
	}
	echo $markup; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- markup is assembled from escaped fields above.
	exit;
}

/**
 * The state change behind the confirmation POST (the caller has verified the form and nonce).
 * Returns array( message, http status, optional page markup ).
 */
function ct_scan_confirm_job( $job_id, $token ) {
	if ( ! ct_scan_lock_acquire() ) {
		return array( 'The request is temporarily busy. Please try again.', 503, '' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	$message = 'This confirmation link is invalid or expired.';
	$response_status = 410;
	$control_markup = '';
	try {
		$row = ct_scan_row( $job_id );
		if ( $row && 'awaiting_confirmation' === $row->status && ! empty( $row->confirmation_token_hash )
			&& hash_equals( $row->confirmation_token_hash, hash( 'sha256', $token ) )
			&& strtotime( $row->confirmation_expires_at . ' UTC' ) > time() && ct_scan_authorization_is_live( $row ) ) {
			// Mailbox control is not control of the website: a job that requires target control waits
			// for it. The challenge token is shown once; only its hash is stored.
			$needs_control = ct_scan_control_required( $row );
			// Two independent secrets: the challenge value (published by design, so world-readable) and
			// the page capability that lets the holder request checks (never published).
			$control_page  = $needs_control ? bin2hex( random_bytes( 32 ) ) : '';
			$control_token = $needs_control ? ct_scan_control_challenge( $row, $control_page ) : '';
			$fields        = array( 'status' => $needs_control ? 'awaiting_control' : 'queued', 'confirmed_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null, 'confirmation_expires_at' => null );
			if ( $needs_control ) {
				$fields['control_token_hash'] = hash( 'sha256', $control_token );
				$fields['control_page_hash']  = hash( 'sha256', $control_page );
				$fields['control_state']      = 'pending';
			}
			$updated = $wpdb->update(
				$table,
				$fields,
				array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_token_hash' => $row->confirmation_token_hash ),
				array_fill( 0, count( $fields ), '%s' ),
				array( '%d', '%s', '%s' )
			);
			if ( 1 === $updated ) {
				if ( $needs_control ) {
					ct_scan_mark_request_status( (int) $row->request_id, 'awaiting_control' );
					$control_markup = ct_scan_control_markup( $row, $control_page, '', 0 );
					$message = 'Your email is confirmed. No screening will run until control of the website is shown.';
				} else {
					ct_scan_mark_request_status( (int) $row->request_id, 'queued' );
					$message = 'Your screening is confirmed and queued. It will run once, within the authorization window.';
				}
				$response_status = 200;
			}
		}
	} finally {
		ct_scan_lock_release();
	}
	if ( 200 === $response_status ) {
		try {
			ct_scan_send_accepted_copy( $job_id );
		} catch ( Throwable $error ) {
			// The copy is independent of the confirmed, queued job.
			unset( $error );
		}
	}
	return array( $message, $response_status, $control_markup );
}

function ct_scan_confirmation_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_confirmation_token_from_request( $_GET );
		if ( '' === $token ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 404 );
		}
		$row = ct_scan_row_by_confirmation_hash( hash( 'sha256', $token ) );
		if ( ! $row || 'awaiting_confirmation' !== $row->status || strtotime( $row->confirmation_expires_at . ' UTC' ) <= time()
			|| ! ct_scan_authorization_is_live( $row ) ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 410 );
		}
		$nonce = wp_create_nonce( 'ct_scan_confirm_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_confirmation_markup( (int) $row->job_id, $token, $nonce, $row->target_origin, $row->terms_version, $row->terms_accepted_at ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the confirmation form to continue.', 405 );
	}
	$token  = ct_scan_confirmation_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_confirm_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This confirmation form is invalid or expired.', 403 );
	}
	list( $message, $response_status, $markup ) = ct_scan_confirm_job( $job_id, $token );
	ct_scan_send_confirmation_page( $message, $response_status, $markup );
}

/**
 * Send the verified contact a retainable copy of what they accepted. Runs after mailbox
 * confirmation, independently of scanning: a failure here never cancels, delays or repeats a
 * scan, and a send is attempted at most once per job (the status is claimed with a
 * compare-and-set before mail is handed off, and an uncertain outcome is never resent).
 * Transport acceptance is not receipt. Off unless config `send_accepted_copy` is true.
 * TODO(owner): review the wording of this message before enabling.
 * Returns 'disabled', 'sent', 'unknown', 'already_handled', or a WP_Error.
 */
function ct_scan_send_accepted_copy( $job_id ) {
	global $wpdb;
	if ( ! ct_scan_enabled() || empty( ct_scan_config()['send_accepted_copy'] ) ) {
		return 'disabled';
	}
	$table = ct_scan_jobs_table();
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		// Same recipient rule as the report path: confirmed, and still the address the signer authorized.
		if ( ! $row || empty( $row->confirmed_at ) || ! is_email( $row->contact_email )
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_email' ) !== $row->contact_email
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_version' ) !== $row->terms_version
			|| strtolower( ct_scan_meta_string( (int) $row->request_id, '_ct_terms_sha256' ) ) !== $row->terms_hash ) {
			return new WP_Error( 'accepted_copy_unavailable', 'The accepted copy requires the confirmed, authorized recipient.' );
		}
		// Re-checked under the queue lock right before the claim: a job that was cancelled, stopped,
		// expired or whose evidence changed since confirmation gets no copy. A confirmed job waiting for
		// proof of target control is live (confirmation sends the copy then); control gates the scan, not the copy.
		if ( ! in_array( $row->status, array( 'awaiting_control', 'queued', 'leased', 'running' ), true ) || ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'accepted_copy_unavailable', 'The accepted copy requires a live authorization.' );
		}
		$claimed = $wpdb->update(
			$table,
			array( 'accepted_copy_status' => 'unknown', 'accepted_copy_at' => ct_scan_utc_now() ),
			array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'not_sent' ),
			array( '%s', '%s' ),
			array( '%d', '%s' )
		);
		if ( 1 !== $claimed ) {
			return 'already_handled';
		}
	} finally {
		ct_scan_lock_release();
	}
	$request_id = (int) $row->request_id;
	$contract   = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$snapshot   = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary    = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	$bound      = '1' === ct_scan_meta_string( $request_id, '_ct_terms_binding' ) && $row->summary_sha256 === hash( 'sha256', $summary ) && hash( 'sha256', $snapshot ) === $row->terms_hash;
	$lines = array(
		'This is the copy of the free PHP2Shell screening agreement and scope that you accepted. Please keep it for your records.',
		'',
		'Website (scan scope): ' . $row->target_origin,
		'Terms version: ' . $row->terms_version,
		'Terms SHA-256: ' . $row->terms_hash,
		'Accepted (UTC): ' . $row->terms_accepted_at,
		'Mailbox confirmed (UTC): ' . $row->confirmed_at,
		'Authorization expires (UTC): ' . $row->authorization_expires_at,
	);
	$attachments = array();
	$tempdir     = '';
	if ( $bound ) {
		$lines[] = 'Target Summary SHA-256: ' . $row->summary_sha256;
		$lines[] = '';
		$lines[] = 'Target Summary as shown to you:';
		$lines[] = $summary;
		// A private, randomly named directory: the attachment is never at a predictable path.
		$candidate = rtrim( sys_get_temp_dir(), '/\\' ) . '/ctat-' . bin2hex( random_bytes( 12 ) );
		if ( @mkdir( $candidate, 0700 ) ) {
			$tempdir = $candidate;
			$path    = $tempdir . '/accepted-terms-' . (int) $row->job_id . '-' . preg_replace( '/[^A-Za-z0-9._-]/', '', $row->terms_version ) . '-' . substr( $row->terms_hash, 0, 12 ) . '.html';
			$written = @file_put_contents( $path, $snapshot );
			// Attach only bytes that reproduce the recorded hash.
			if ( strlen( $snapshot ) === $written && hash_file( 'sha256', $path ) === $row->terms_hash ) {
				$attachments[] = $path;
				$lines[]       = 'The attached file contains the exact terms text you were shown; its SHA-256 is the value above.';
			}
		}
	}
	$lines[] = '';
	$lines[] = $contract;
	$status  = 'unknown';
	try {
		$sent   = wp_mail( $row->contact_email, 'Your accepted PHP2Shell screening agreement', implode( "\n", $lines ), '', $attachments );
		$status = $sent ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$status = 'unknown';
	}
	if ( '' !== $tempdir ) {
		foreach ( (array) glob( $tempdir . '/*' ) as $leftover ) {
			@unlink( $leftover );
		}
		@rmdir( $tempdir );
	}
	$wpdb->update( $table, array( 'accepted_copy_status' => $status ), array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	return 'accepted' === $status ? 'sent' : 'unknown';
}

function ct_scan_row_by_confirmation_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE confirmation_token_hash = %s LIMIT 1", $hash ) );
}
add_action( 'admin_post_nopriv_ct_scan_confirm', 'ct_scan_confirmation_handler' );
add_action( 'admin_post_ct_scan_confirm', 'ct_scan_confirmation_handler' );


/**
 * Exact-target control. Mailbox confirmation shows control of an email address, not of the website.
 * For jobs frozen with control_required the customer proves control of the exact hostname by
 * publishing the challenge as a DNS TXT record at `_ct-scan-challenge.<host>` (value
 * `ct-scan-verify=<token>`) or serving it at `https://<host>/.well-known/ct-scan-challenge.txt`, then
 * asks for a check. At most three checks, one minute apart, each one TXT lookup or one HTTPS request
 * (fixed path, no redirects, 4 KiB, 10 s). A recorded manual authority review can stand in. A failed
 * challenge never falls back to a scan: after three failures the job is `blocked`.
 * TODO(owner): the wording of these customer-facing pages is functional only.
 */
/**
 * The challenge value shown to the customer. It is derived from the page capability with a keyed
 * hash, so the page can show it again without storing it, while someone who reads the published
 * challenge learns nothing that lets them open the page and use up the checks.
 */
function ct_scan_control_challenge( $row, $page_token ) {
	return hash_hmac( 'sha256', 'ct-scan-challenge-v1|' . (int) $row->job_id . '|' . $row->scope_hash, $page_token );
}

function ct_scan_control_markup( $row, $page_token, $notice, $attempts_used ) {
	$limits    = ct_scan_control_limits();
	$host      = (string) wp_parse_url( $row->target_origin, PHP_URL_HOST );
	$challenge = ct_scan_control_challenge( $row, $page_token );
	$action    = esc_url( admin_url( 'admin-post.php' ) );
	$nonce     = wp_create_nonce( 'ct_scan_control_' . (int) $row->job_id . '_' . $page_token );
	$link      = esc_url( add_query_arg( array( 'action' => 'ct_scan_control', 'job' => (int) $row->job_id, 'ctl' => $page_token ), admin_url( 'admin-post.php' ) ) );
	$html  = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Show control of your website</title><body><main><h1>Show control of your website</h1>';
	if ( '' !== $notice ) {
		$html .= '<p><strong>' . esc_html( $notice ) . '</strong></p>';
	}
	$html .= '<p>No screening runs until control of <strong>' . esc_html( $host ) . '</strong> is shown. Publish ONE of the following, then press Check.</p>';
	$html .= '<p>DNS TXT record at <code>' . esc_html( $limits['dns_label'] . '.' . $host ) . '</code> with the value:<br><code>' . esc_html( $limits['dns_prefix'] . $challenge ) . '</code><br><small>The TXT record must be at that exact name: a CNAME there is not followed. Wait until the record is visible in public DNS before checking; a check made too early can be answered from a cached "no record" and still uses one of your checks.</small></p>';
	$html .= '<p>or the file <code>https://' . esc_html( $host . $limits['path'] ) . '</code> whose entire content is:<br><code>' . esc_html( $challenge ) . '</code></p>';
	$html .= '<p>Keep this page\'s address private: it is the only way to return here and to request checks. Checks used: ' . (int) $attempts_used . ' of ' . (int) $limits['max_attempts'] . '; at least one minute apart.</p>';
	$html .= '<form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_control"><input type="hidden" name="job" value="' . esc_attr( (string) (int) $row->job_id ) . '"><input type="hidden" name="ctl" value="' . esc_attr( $page_token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '">';
	$html .= '<label><input type="radio" name="method" value="dns_txt" checked> I published the DNS record</label><br><label><input type="radio" name="method" value="https_file"> I published the file</label><br><button type="submit">Check now</button></form>';
	$html .= '<p><small>Return address: ' . $link . '</small></p></main></body></html>';
	return $html;
}

function ct_scan_control_token_from_request( $source ) {
	if ( ! isset( $source['ctl'] ) || ! is_string( $source['ctl'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['ctl'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

/** Schedule one control check for the customer's chosen method, under the disclosed limits. */
function ct_scan_request_control_check( $job_id, $token, $method ) {
	global $wpdb;
	$limits = ct_scan_control_limits();
	if ( ! in_array( $method, array( 'dns_txt', 'https_file' ), true ) ) {
		return new WP_Error( 'control_method_invalid', 'Choose the DNS record or the file.' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The request is temporarily busy. Please try again.' );
	}
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_page_hash ) || ! hash_equals( $row->control_page_hash, hash( 'sha256', $token ) )
			|| ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'control_link_invalid', 'This link is invalid or expired.' );
		}
		if ( 'pending' !== $row->control_state ) {
			return new WP_Error( 'control_check_in_progress', 'A check is already scheduled or running.' );
		}
		$now_ms = (int) floor( microtime( true ) * 1000 );
		if ( (int) $row->control_attempts >= $limits['max_attempts'] ) {
			return new WP_Error( 'control_attempts_exhausted', 'All checks were used.' );
		}
		if ( null !== $row->control_last_attempt_ms && $now_ms < (int) $row->control_last_attempt_ms + $limits['min_interval_ms'] ) {
			return new WP_Error( 'control_too_soon', 'Wait at least one minute between checks.' );
		}
		$updated = $wpdb->update(
			$table,
			array( 'control_state' => 'requested', 'control_requested_method' => $method ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'pending', 'control_attempts' => (int) $row->control_attempts ),
			array( '%s', '%s' ),
			array( '%d', '%s', '%s', '%d' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'control_write_failed', 'The check could not be scheduled. Please try again.' );
		}
	} finally {
		ct_scan_lock_release();
	}
	return 'scheduled';
}

function ct_scan_control_handler() {
	$method_http = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	$source      = 'POST' === $method_http ? $_POST : $_GET;
	$token       = ct_scan_control_token_from_request( $source );
	$job_id      = isset( $source['job'] ) && is_scalar( $source['job'] ) ? absint( wp_unslash( $source['job'] ) ) : 0;
	if ( ! in_array( $method_http, array( 'GET', 'POST' ), true ) ) {
		ct_scan_send_confirmation_page( 'Use the link you were given.', 405 );
	}
	if ( ! $job_id || '' === $token ) {
		ct_scan_send_confirmation_page( 'This link is invalid or expired.', 404 );
	}
	$row = ct_scan_row( $job_id );
	if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_page_hash ) || ! hash_equals( $row->control_page_hash, hash( 'sha256', $token ) ) || ! ct_scan_authorization_is_live( $row ) ) {
		ct_scan_send_confirmation_page( 'This link is invalid or expired.', 410 );
	}
	if ( 'GET' === $method_http ) {
		ct_scan_send_confirmation_page( '', 200, ct_scan_control_markup( $row, $token, '', (int) $row->control_attempts ) );
	}
	if ( ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] ) || ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_control_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This form is invalid or expired. Open the link again.', 403 );
	}
	$choice = isset( $_POST['method'] ) && is_string( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';
	$result = ct_scan_request_control_check( $job_id, $token, $choice );
	$notice = array(
		'scheduled'                 => 'Check scheduled. It runs within a minute; return to this page to see the outcome.',
		'control_check_in_progress' => 'A check is already scheduled or running.',
		'control_too_soon'          => 'Wait at least one minute between checks.',
		'control_attempts_exhausted' => 'All checks were used.',
		'control_method_invalid'    => 'Choose the DNS record or the file.',
		'queue_busy'                => 'The request is temporarily busy. Please try again.',
	);
	$key     = is_wp_error( $result ) ? $result->get_error_code() : $result;
	$current = ct_scan_row( $job_id );
	$current = $current ? $current : $row;
	ct_scan_send_confirmation_page( '', 200, ct_scan_control_markup( $current, $token, isset( $notice[ $key ] ) ? $notice[ $key ] : 'The check could not be scheduled.', (int) $current->control_attempts ) );
}
add_action( 'admin_post_nopriv_ct_scan_control', 'ct_scan_control_handler' );
add_action( 'admin_post_ct_scan_control', 'ct_scan_control_handler' );

/** Recorded manual authority review: names the reviewer, evidence, target, time and expiry. */
function ct_scan_admin_record_authority_review( $job_id, $evidence_note ) {
	global $wpdb;
	$user = wp_get_current_user();
	if ( ! $user || ! $user->exists() || ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'authority_review_forbidden', 'Only an administrator can record an authority review.' );
	}
	$note = is_string( $evidence_note ) ? trim( wp_strip_all_tags( $evidence_note ) ) : '';
	if ( strlen( $note ) < 20 || strlen( $note ) > 1000 ) {
		return new WP_Error( 'authority_review_evidence_required', 'Describe the evidence reviewed (20 to 1000 characters).' );
	}
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || 'awaiting_control' !== $row->status || empty( $row->control_required ) || ! empty( $row->revoked_at ) || ! ct_scan_authorization_is_live( $row ) ) {
			return new WP_Error( 'authority_review_unavailable', 'This job is not waiting for target control.' );
		}
		if ( 'checking' === $row->control_state ) {
			return new WP_Error( 'authority_review_check_in_progress', 'A DNS or file check for this job is in progress. Wait for its result (at most two minutes), then reload this page and record the review if the job is still waiting.' );
		}
		$now      = ct_scan_utc_now();
		$evidence = wp_json_encode( array(
			'method'      => 'manual_review',
			'reviewer_id' => (int) $user->ID,
			'reviewer'    => sanitize_user( $user->user_login, true ),
			'target'      => $row->target_origin,
			'evidence'    => $note,
			'reviewed_at' => $now,
			'valid_until' => $row->authorization_expires_at,
		), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$updated  = $wpdb->update(
			$table,
			array( 'status' => 'queued', 'control_state' => 'none', 'control_method' => 'manual_review', 'control_verified_at' => $now, 'control_valid_until' => $row->authorization_expires_at, 'control_evidence' => $evidence, 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => $row->control_state ),
			array_fill( 0, 10, '%s' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'authority_review_write_failed', 'The review could not be durably recorded.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'queued' );
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_stop_token_from_request( $source ) {
	if ( ! isset( $source['stop'] ) || ! is_string( $source['stop'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['stop'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_row_by_stop_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE stop_token_hash = %s LIMIT 1", $hash ) );
}

/**
 * Customer stop: request-bound and idempotent, serialized with claims, starts, results and
 * request admissions by the queue lock. A cancelled job is rejected by the start, admit and
 * result endpoints. A request already admitted when the stop commits may finish within its
 * ten-second timeout; no further request is admitted. Waits briefly for the lock so that a
 * concurrent admission cannot make the customer's stop fail.
 * Returns 'stopped', 'already_stopped', 'already_finished', or a WP_Error.
 */
function ct_scan_customer_stop( $job_id, $token ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The request is temporarily busy. Please try again.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->stop_token_hash ) || '' === $token || ! hash_equals( $row->stop_token_hash, hash( 'sha256', $token ) ) ) {
			return new WP_Error( 'stop_link_invalid', 'This stop link is invalid.' );
		}
		if ( 'cancelled' === $row->status ) {
			return 'already_stopped';
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			return 'already_finished';
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'cancelled', 'error_code' => 'customer_stopped', 'finished_at' => $now, 'confirmation_token_hash' => null, 'confirmation_expires_at' => null, 'lease_hash' => null, 'lease_until' => null, 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ),
			array( 'job_id' => (int) $row->job_id, 'status' => $row->status ),
			null,
			array( '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'stop_write_failed', 'The stop could not be recorded. Please try again or contact support@complete.tech.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'customer_stopped' );
	} finally {
		ct_scan_lock_release();
	}
	return 'stopped';
}

function ct_scan_stop_markup( $job_id, $token, $nonce, $target ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Stop website screening</title><body><main><h1>Stop your website screening</h1><p>Stop the screening of this website:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>No new screening will start after you press Stop. A check that has already started may finish its current requests. Opening this page alone changes nothing.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_stop"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="stop" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Stop screening</button></form></main></body></html>';
}

function ct_scan_stop_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_stop_token_from_request( $_GET );
		$row   = '' === $token ? null : ct_scan_row_by_stop_hash( hash( 'sha256', $token ) );
		if ( ! $row ) {
			ct_scan_send_confirmation_page( 'This stop link is invalid.', 404 );
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			ct_scan_send_confirmation_page( 'cancelled' === $row->status ? 'This screening is already stopped.' : 'This screening has already finished. Nothing further will run.' );
		}
		$nonce = wp_create_nonce( 'ct_scan_stop_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_stop_markup( (int) $row->job_id, $token, $nonce, $row->target_origin ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the stop form to continue.', 405 );
	}
	$token  = ct_scan_stop_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_stop_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This stop form is invalid or expired. Open the stop link again.', 403 );
	}
	$result = ct_scan_customer_stop( $job_id, $token );
	if ( is_wp_error( $result ) ) {
		ct_scan_send_confirmation_page( $result->get_error_message(), 'queue_busy' === $result->get_error_code() ? 503 : 410 );
	}
	$messages = array(
		'stopped'          => 'Your screening is stopped. No new screening will start.',
		'already_stopped'  => 'This screening is already stopped.',
		'already_finished' => 'This screening has already finished. Nothing further will run.',
	);
	ct_scan_send_confirmation_page( $messages[ $result ] );
}
add_action( 'admin_post_nopriv_ct_scan_stop', 'ct_scan_stop_handler' );
add_action( 'admin_post_ct_scan_stop', 'ct_scan_stop_handler' );

function ct_scan_rest_response( $status, $payload ) {
	return new WP_REST_Response( $payload, (int) $status );
}

function ct_scan_rest_error( $status, $code ) {
	return ct_scan_rest_response( $status, array( 'error' => sanitize_key( $code ) ) );
}

/** Authenticate and consume a unique, short-lived worker nonce. */
function ct_scan_rest_authenticate( WP_REST_Request $request, $route ) {
	if ( ! ct_scan_enabled() || get_option( 'ct_scan_schema_version' ) !== CT_SCAN_SCHEMA_VERSION ) {
		return new WP_Error( 'ct_scan_disabled', 'Worker API is disabled.', array( 'status' => 503 ) );
	}
	$body = $request->get_body();
	if ( ! is_string( $body ) || strlen( $body ) > 65536 ) {
		return new WP_Error( 'ct_scan_body_too_large', 'Request body is too large.', array( 'status' => 413 ) );
	}
	$timestamp = $request->get_header( 'x-ct-timestamp' );
	$nonce     = $request->get_header( 'x-ct-nonce' );
	$signature = $request->get_header( 'x-ct-signature' );
	if ( ! is_string( $timestamp ) || ! preg_match( '/\A[0-9]{10}\z/', $timestamp )
		|| abs( time() - (int) $timestamp ) > 300
		|| ! is_string( $nonce ) || ! preg_match( '/\A[a-f0-9]{32}\z/i', $nonce )
		|| ! is_string( $signature ) || ! preg_match( '/\A[a-f0-9]{64}\z/i', $signature ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	$signing = $timestamp . "\n" . strtolower( $nonce ) . "\nPOST\n" . $route . "\n" . hash( 'sha256', $body );
	$expected = hash_hmac( 'sha256', $signing, ct_scan_config()['worker_hmac_secret'] );
	if ( ! hash_equals( $expected, strtolower( $signature ) ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	global $wpdb;
	$table = ct_scan_nonces_table();
	$nonce_hash = hash( 'sha256', strtolower( $nonce ) );
	$inserted = $wpdb->query( $wpdb->prepare(
		"INSERT IGNORE INTO {$table} (nonce_hash, expires_at) VALUES (%s, %s)",
		$nonce_hash,
		gmdate( 'Y-m-d H:i:s', time() + 600 )
	) );
	if ( 1 !== $inserted ) {
		return new WP_Error( 'ct_scan_replay', 'Worker authentication failed.', array( 'status' => 409 ) );
	}
	return $body;
}

function ct_scan_decode_request_body( $body ) {
	$data = json_decode( $body, true );
	if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
		return new WP_Error( 'ct_scan_json_invalid', 'Expected a JSON object.' );
	}
	return $data;
}

function ct_scan_expected_keys( $data, $keys ) {
	$actual = array_keys( $data );
	sort( $actual );
	sort( $keys );
	return $actual === $keys;
}

function ct_scan_is_list( $value ) {
	return is_array( $value ) && ( array() === $value || array_keys( $value ) === range( 0, count( $value ) - 1 ) );
}

function ct_scan_claim( WP_REST_Request $request ) {
	$response = ct_scan_claim_locked( $request );
	// The worker polls this route every few seconds; retention piggybacks on it, outside the queue lock, and
	// only on a poll that hands out no job, so a lease is never delayed by a retention run.
	if ( $response instanceof WP_REST_Response && 200 === $response->get_status() ) {
		$data = $response->get_data();
		if ( is_array( $data ) && array_key_exists( 'job', $data ) && null === $data['job'] ) {
			ct_scan_retention_run_safely(); // retention must never affect a claim
		}
	}
	return $response;
}

function ct_scan_claim_locked( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/claim' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array() ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		// One piece of target traffic at a time worker-wide: a scan, or a control check in progress.
		$active = $wpdb->get_var( "SELECT job_id FROM {$table} WHERE status IN ('leased','running') OR (status = 'awaiting_control' AND control_state = 'checking') LIMIT 1" );
		if ( $active ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'queued' AND attempts = 0 ORDER BY created_at ASC, job_id ASC LIMIT 1" );
		if ( ! $row ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$lease       = bin2hex( random_bytes( 32 ) );
		$expiry      = strtotime( $row->authorization_expires_at . ' UTC' );
		$lease_until = min( time() + 300, $expiry );
		if ( $lease_until <= time() ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'leased', 'lease_hash' => hash( 'sha256', $lease ), 'lease_until' => gmdate( 'Y-m-d H:i:s', $lease_until ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'queued', 'attempts' => 0 ),
			array( '%s', '%s', '%s' ),
			array( '%d', '%s', '%d' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 503, 'claim_race' );
		}
		return ct_scan_rest_response( 200, array(
			'job' => array(
				'id'          => (int) $row->job_id,
				'target'      => $row->target_origin,
				'scope_hash'  => $row->scope_hash,
				'terms_hash'  => $row->terms_hash,
				'expires_at'  => (int) $expiry,
				'lease'       => $lease,
				'lease_until' => (int) $lease_until,
			),
		) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_callback_payload( $data ) {
	if ( ! isset( $data['id'], $data['lease'], $data['scope_hash'] ) || ! is_int( $data['id'] ) || $data['id'] < 1
		|| ! is_string( $data['lease'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['lease'] )
		|| ! is_string( $data['scope_hash'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['scope_hash'] ) ) {
		return false;
	}
	return true;
}

function ct_scan_start( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/start' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash' ) ) || ! ct_scan_callback_payload( $data ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row || 'leased' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( strtotime( $row->lease_until . ' UTC' ) <= time() || 0 !== (int) $row->attempts ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		$now = ct_scan_utc_now();
		$authorization_expiry = strtotime( $row->authorization_expires_at . ' UTC' );
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'running', 'attempts' => 1, 'started_at' => $now, 'lease_until' => gmdate( 'Y-m-d H:i:s', min( time() + 300, $authorization_expiry ) ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'leased', 'attempts' => 0, 'lease_hash' => $row->lease_hash ),
			array( '%s', '%d', '%s', '%s' ),
			array( '%d', '%s', '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'start_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'running' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

/**
 * Per-request admission decision. The sandboxed scanner holds no key: before every
 * connection to the target, the supervisor asks this guard through the signed
 * `admit` route. The caller MUST hold the queue lock, so this decision is
 * serialized with customer stop, operator revocation, expiry, lease changes and
 * every other admission. Returns array( http_status, payload ).
 *
 * `http` reserves one request from the frozen profile's budget and records the
 * admission time in the same compare-and-set update; the reservation is consumed
 * at once and is valid for ct_scan_profile_limits()['valid_ms']. `probe` only
 * reports whether the job is still live (no budget, no pacing).
 *
 * Nothing here is permissive on failure: an unknown profile, a clock that moved
 * backwards, a failed write, or an unconfirmed recipient is a refusal.
 */
function ct_scan_admit_locked( $data, $now_ms ) {
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$refuse = static function ( $status, $reason, $extra = array() ) {
		return array( (int) $status, array_merge( array( 'ok' => false, 'reason' => sanitize_key( $reason ) ), $extra ) );
	};
	// No table-wide maintenance here: probes run every couple of seconds under the same
	// lock as Stop, so this path stays short. Expiry and lease are checked on the row.
	$row = ct_scan_row( $data['id'] );
	if ( ! $row ) {
		return $refuse( 410, 'job_not_found' );
	}
	if ( 'running' === $row->status && strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'error_code' => 'authorization_expired', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null, 'confirmation_token_hash' => null ), array( 'job_id' => (int) $row->job_id, 'status' => 'running' ), array( '%s', '%s', '%s', '%s', '%s', '%s' ), array( '%d', '%s' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'expired', 'authorization_expired' );
		return $refuse( 410, 'job_expired' );
	}
	if ( 'cancelled' === $row->status ) {
		return $refuse( 410, 'job_cancelled' );
	}
	if ( 'expired' === $row->status ) {
		return $refuse( 410, 'job_expired' );
	}
	if ( 'running' !== $row->status || 1 !== (int) $row->attempts ) {
		return $refuse( 410, 'job_not_running' );
	}
	if ( empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
		|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
		return $refuse( 410, 'lease_invalid_or_expired' );
	}
	if ( empty( $row->confirmed_at ) ) {
		return $refuse( 410, 'recipient_unconfirmed' );
	}
	if ( ! ct_scan_authorization_is_live( $row ) ) {
		$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		return $refuse( 410, 'authorization_revoked_or_expired' );
	}
	$limits = ct_scan_profile_limits( $row->profile_id );
	if ( ! $limits ) {
		return $refuse( 410, 'profile_unknown' );
	}
	if ( 'probe' === $data['kind'] ) {
		return array( 200, array( 'ok' => true, 'live' => true ) );
	}
	$last = null === $row->last_admit_ms ? null : (int) $row->last_admit_ms;
	if ( null !== $last ) {
		if ( $now_ms + $limits['min_interval_ms'] < $last ) {
			// The clock moved backwards by more than the pacing interval: do not guess.
			return $refuse( 410, 'clock_anomaly' );
		}
		$wait = $last + $limits['min_interval_ms'] - $now_ms;
		if ( $wait > 0 ) {
			return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => (int) min( $wait, $limits['min_interval_ms'] ) ) );
		}
	}
	$used = (int) $row->http_admitted;
	if ( $used >= $limits['http_requests'] ) {
		return $refuse( 409, 'budget_exhausted' );
	}
	$updated = $wpdb->update(
		$table,
		array( 'http_admitted' => $used + 1, 'last_admit_ms' => $now_ms ),
		array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash, 'http_admitted' => $used ),
		array( '%d', '%d' ),
		array( '%d', '%s', '%s', '%d' )
	);
	if ( 1 !== $updated ) {
		return $refuse( 503, 'admission_write_failed' );
	}
	return array( 200, array(
		'ok'             => true,
		'admitted'       => true,
		'sequence'       => $used + 1,
		'valid_ms'       => (int) $limits['valid_ms'],
		'timeout_ms'     => (int) $limits['timeout_ms'],
		'http_remaining' => (int) ( $limits['http_requests'] - $used - 1 ),
	) );
}

function ct_scan_admit( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/admit' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash', 'kind' ) ) || ! ct_scan_callback_payload( $data )
		|| ! is_string( $data['kind'] ) || ! in_array( $data['kind'], array( 'http', 'probe', 'control', 'control_probe' ), true ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		// Fail closed: a refusal here ends the screening rather than risking an unserialized send.
		return ct_scan_rest_response( 503, array( 'ok' => false, 'reason' => 'queue_busy' ) );
	}
	try {
		$now_ms   = (int) floor( microtime( true ) * 1000 );
		$decision = in_array( $data['kind'], array( 'control', 'control_probe' ), true )
			? ct_scan_admit_control_locked( $data, $now_ms )
			: ct_scan_admit_locked( $data, $now_ms );
	} catch ( Throwable $error ) {
		$decision = array( 503, array( 'ok' => false, 'reason' => 'admission_error' ) );
	} finally {
		ct_scan_lock_release();
	}
	return ct_scan_rest_response( $decision[0], $decision[1] );
}

function ct_scan_clean_result_line( $value, $limit = 500 ) {
	return is_string( $value ) && strlen( $value ) <= $limit;
}

function ct_scan_result_url_matches_scope( $url, $target ) {
	if ( ! is_string( $url ) || '' === $url || strlen( $url ) > 4096 ) {
		return false;
	}
	$parts = wp_parse_url( $url );
	$base  = wp_parse_url( $target );
	if ( ! is_array( $parts ) || ! is_array( $base ) || empty( $parts['scheme'] ) || empty( $parts['host'] )
		|| isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
		return false;
	}
	$scheme = strtolower( $parts['scheme'] );
	$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	$base_port = 'https' === $base['scheme'] ? 443 : 80;
	return in_array( $scheme, array( 'http', 'https' ), true )
		&& strtolower( $parts['host'] ) === $base['host']
		&& $port === ( 'https' === $scheme ? 443 : 80 )
		&& ( 'https' !== $base['scheme'] || 'https' === $scheme );
}

/** Validate the small, single-result checker payload before persisting it. */
function ct_scan_validate_result( $result, $row, $stored_snapshot = false ) {
	if ( ! is_array( $result ) || count( $result ) > 64 ) {
		return new WP_Error( 'result_invalid', 'result_invalid' );
	}
	$required = array(
		'input_url', 'final_url', 'status', 'fetch_status', 'http_status', 'wordpress_version', 'php_version', 'server', 'powered_by', 'title',
		'evidence', 'asset_version_hints', 'notes', 'checked_at', 'php_version_candidates', 'php_evidence', 'php2shell_status',
		'php2shell_version_status', 'php2shell_fixed_version', 'php2shell_exploitability', 'php2shell_cves', 'php2shell_rules_as_of',
		'php2shell_sources', 'php2shell_notes', 'php2shell_recommendation',
	);
	if ( ! ct_scan_expected_keys( $result, $required ) ) {
		return new WP_Error( 'result_schema_mismatch', 'result_schema_mismatch' );
	}
	$version_states = array( 'version_not_disclosed', 'conflicting_versions', 'unrecognized_or_partial_version', 'branch_requires_vendor_review', 'prerelease_unverified', 'vendor_build_unverified', 'below_upstream_fix', 'at_or_above_upstream_fix' );
	$config = ct_scan_config();
	if ( ! is_string( $result['input_url'] ) || $result['input_url'] !== $row->target_origin
		|| ! is_string( $result['final_url'] )
		|| ! in_array( $result['status'], array( 'wordpress', 'likely_wordpress', 'no_evidence', 'uncertain', 'blocked', 'error' ), true )
		|| ! in_array( $result['fetch_status'], array( 'ok', 'blocked', 'timeout', 'dns_error' ), true )
		|| ! in_array( $result['php2shell_status'], array( 'potentially_affected', 'fixed_version_reported', 'unknown' ), true )
		|| ! is_string( $result['php2shell_version_status'] ) || ! in_array( $result['php2shell_version_status'], $version_states, true )
		|| 'not_tested' !== $result['php2shell_exploitability']
		|| ! is_string( $result['php2shell_rules_as_of'] ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}\z/', $result['php2shell_rules_as_of'] )
		|| ! checkdate( (int) substr( $result['php2shell_rules_as_of'], 5, 2 ), (int) substr( $result['php2shell_rules_as_of'], 8, 2 ), (int) substr( $result['php2shell_rules_as_of'], 0, 4 ) )
		|| ( ! $stored_snapshot && $result['php2shell_rules_as_of'] !== $config['expected_rules_as_of'] )
		|| ! is_string( $result['checked_at'] ) || strlen( $result['checked_at'] ) > 64
		|| ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/', $result['checked_at'] )
		|| ! is_string( $result['php_version'] ) || strlen( $result['php_version'] ) > 128
		|| ! is_string( $result['wordpress_version'] ) || strlen( $result['wordpress_version'] ) > 128
		|| ! is_string( $result['php2shell_fixed_version'] ) || strlen( $result['php2shell_fixed_version'] ) > 32 ) {
		return new WP_Error( 'result_semantics_invalid', 'result_semantics_invalid' );
	}
	if ( '' !== $result['final_url'] && ! ct_scan_result_url_matches_scope( $result['final_url'], $row->target_origin ) ) {
		return new WP_Error( 'result_scope_mismatch', 'result_scope_mismatch' );
	}
	if ( null !== $result['http_status'] && ( ! is_int( $result['http_status'] ) || $result['http_status'] < 100 || $result['http_status'] > 599 ) ) {
		return new WP_Error( 'result_http_status_invalid', 'result_http_status_invalid' );
	}
	foreach ( array( 'server', 'powered_by', 'title', 'php2shell_recommendation' ) as $key ) {
		if ( ! ct_scan_clean_result_line( $result[ $key ], 2048 ) ) {
			return new WP_Error( 'result_text_invalid', 'result_text_invalid' );
		}
	}
	foreach ( array( 'evidence', 'asset_version_hints', 'notes', 'php_version_candidates', 'php_evidence', 'php2shell_cves', 'php2shell_sources', 'php2shell_notes' ) as $key ) {
		if ( ! is_array( $result[ $key ] ) || ! ct_scan_is_list( $result[ $key ] ) || count( $result[ $key ] ) > 100 ) {
			return new WP_Error( 'result_list_invalid', 'result_list_invalid' );
		}
		foreach ( $result[ $key ] as $entry ) {
			$limit = in_array( $key, array( 'php_version_candidates' ), true ) ? 128 : 2048;
			if ( ! ct_scan_clean_result_line( $entry, $limit ) ) {
				return new WP_Error( 'result_list_item_invalid', 'result_list_item_invalid' );
			}
		}
	}
	if ( array_values( $result['php2shell_cves'] ) !== array( 'CVE-2026-109618', 'CVE-2026-109619' ) ) {
		return new WP_Error( 'result_cves_invalid', 'result_cves_invalid' );
	}
	$encoded = wp_json_encode( $result );
	if ( ! is_string( $encoded ) || strlen( $encoded ) > 32768 ) {
		return new WP_Error( 'result_too_large', 'result_too_large' );
	}
	return $encoded;
}

function ct_scan_canonicalize( $value ) {
	if ( ! is_array( $value ) ) {
		return $value;
	}
	if ( ct_scan_is_list( $value ) ) {
		return array_map( 'ct_scan_canonicalize', $value );
	}
	ksort( $value, SORT_STRING );
	foreach ( $value as $key => $item ) {
		$value[ $key ] = ct_scan_canonicalize( $item );
	}
	return $value;
}

function ct_scan_result( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/result' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	$keys = array( 'id', 'lease', 'scope_hash', 'outcome', 'result', 'error', 'checker_revision' );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, $keys ) || ! ct_scan_callback_payload( $data )
		|| ! in_array( $data['outcome'], array( 'completed', 'failed' ), true ) || ! is_string( $data['checker_revision'] )
		|| ! preg_match( '/\A[a-f0-9]{40}\z/', $data['checker_revision'] ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$config = ct_scan_config();
	if ( ! hash_equals( strtolower( $config['expected_checker_revision'] ), strtolower( $data['checker_revision'] ) ) ) {
		return ct_scan_rest_error( 422, 'checker_revision_mismatch' );
	}
	$encoded_result = null;
	if ( 'completed' === $data['outcome'] ) {
		if ( ! is_array( $data['result'] ) || '' !== $data['error'] ) {
			return ct_scan_rest_error( 400, 'result_invalid' );
		}
	} else {
		if ( null !== $data['result'] || ! is_string( $data['error'] ) || ! preg_match( '/\A[a-z][a-z0-9_]{0,63}\z/', $data['error'] ) ) {
			return ct_scan_rest_error( 400, 'failure_receipt_invalid' );
		}
	}
	$canonical = wp_json_encode( ct_scan_canonicalize( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	if ( ! is_string( $canonical ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$receipt_hash = hash( 'sha256', $canonical );
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row ) {
			return ct_scan_rest_error( 410, 'job_not_found' );
		}
		if ( in_array( $row->status, array( 'completed', 'failed' ), true ) && ! empty( $row->receipt_hash ) ) {
			return hash_equals( $row->receipt_hash, $receipt_hash )
				? ct_scan_rest_response( 200, array( 'ok' => true ) )
				: ct_scan_rest_error( 409, 'receipt_conflict' );
		}
		if ( in_array( $row->status, array( 'cancelled', 'expired', 'failed_unknown' ), true ) ) {
			return ct_scan_rest_error( 410, 'job_permanently_rejected' );
		}
		if ( 'running' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		if ( 'completed' === $data['outcome'] ) {
			// A completed result is only credible if the guard admitted at least one request for this job.
			if ( (int) $row->http_admitted < 1 ) {
				return ct_scan_rest_error( 409, 'no_admission' );
			}
			$encoded_result = ct_scan_validate_result( $data['result'], $row );
			if ( is_wp_error( $encoded_result ) ) {
				return ct_scan_rest_error( 422, $encoded_result->get_error_code() );
			}
		}
		$state = 'completed' === $data['outcome'] ? 'completed' : 'failed';
		$updated = $wpdb->update(
			$table,
			array(
				'status'           => $state,
				'outcome'          => $data['outcome'],
				'error_code'       => 'failed' === $data['outcome'] ? $data['error'] : null,
				'checker_revision' => strtolower( $data['checker_revision'] ),
				'result_json'      => $encoded_result,
				'receipt_hash'     => $receipt_hash,
				'finished_at'      => ct_scan_utc_now(),
				'lease_hash'       => null,
				'lease_until'      => null,
			),
			array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash ),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'result_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, $state, 'failed' === $state ? $data['error'] : '' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

/**
 * Admission for the single request of a control check (kind `control`) or a liveness probe of a
 * control task (`control_probe`). Same contract as ct_scan_admit_locked(): called under the queue
 * lock, refuses on any doubt, and consumes the attempt in the same compare-and-set as the decision.
 * The check budget is the disclosed three attempts, one minute apart.
 */
function ct_scan_admit_control_locked( $data, $now_ms ) {
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$limits = ct_scan_control_limits();
	$refuse = static function ( $status, $reason, $extra = array() ) {
		return array( (int) $status, array_merge( array( 'ok' => false, 'reason' => sanitize_key( $reason ) ), $extra ) );
	};
	$row = ct_scan_row( $data['id'] );
	if ( ! $row ) {
		return $refuse( 410, 'job_not_found' );
	}
	if ( 'awaiting_control' === $row->status && strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'error_code' => 'authorization_expired', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control' ), null, array( '%d', '%s' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'expired', 'authorization_expired' );
		return $refuse( 410, 'job_expired' );
	}
	if ( 'cancelled' === $row->status ) {
		return $refuse( 410, 'job_cancelled' );
	}
	if ( 'expired' === $row->status ) {
		return $refuse( 410, 'job_expired' );
	}
	if ( 'awaiting_control' !== $row->status || empty( $row->control_required ) ) {
		return $refuse( 410, 'job_not_awaiting_control' );
	}
	if ( 'checking' !== $row->control_state || empty( $row->control_lease_hash ) || ! hash_equals( $row->control_lease_hash, hash( 'sha256', $data['lease'] ) )
		|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->control_lease_until . ' UTC' ) <= time() ) {
		return $refuse( 410, 'lease_invalid_or_expired' );
	}
	if ( empty( $row->confirmed_at ) ) {
		return $refuse( 410, 'recipient_unconfirmed' );
	}
	if ( ! ct_scan_authorization_is_live( $row ) ) {
		$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		return $refuse( 410, 'authorization_revoked_or_expired' );
	}
	if ( 'control_probe' === $data['kind'] ) {
		return array( 200, array( 'ok' => true, 'live' => true ) );
	}
	// One lease, one check: a lease that was already admitted is never admitted again, however
	// long it has left. The lease (two minutes) outlives the one-minute interval between checks.
	if ( ! empty( $row->control_admitted ) ) {
		return $refuse( 409, 'already_admitted' );
	}
	$used = (int) $row->control_attempts;
	if ( $used >= $limits['max_attempts'] ) {
		return $refuse( 409, 'budget_exhausted' );
	}
	if ( null !== $row->control_last_attempt_ms ) {
		$last = (int) $row->control_last_attempt_ms;
		if ( $now_ms + $limits['min_interval_ms'] < $last ) {
			return $refuse( 410, 'clock_anomaly' );
		}
		$wait = $last + $limits['min_interval_ms'] - $now_ms;
		if ( $wait > 0 ) {
			return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => (int) $wait ) );
		}
	}
	$updated = $wpdb->update(
		$table,
		array( 'control_attempts' => $used + 1, 'control_last_attempt_ms' => $now_ms, 'control_admitted' => 1 ),
		array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'checking', 'control_lease_hash' => $row->control_lease_hash, 'control_attempts' => $used, 'control_admitted' => 0 ),
		array( '%d', '%d', '%d' ),
		array( '%d', '%s', '%s', '%s', '%d', '%d' )
	);
	if ( 1 !== $updated ) {
		return $refuse( 503, 'admission_write_failed' );
	}
	return array( 200, array(
		'ok'             => true,
		'admitted'       => true,
		'sequence'       => $used + 1,
		'valid_ms'       => (int) $limits['valid_ms'],
		'timeout_ms'     => (int) $limits['timeout_ms'],
		'http_remaining' => (int) ( $limits['max_attempts'] - $used - 1 ),
	) );
}

/** Worker: take one scheduled control check. Consumes nothing; the attempt is consumed at admission. */
function ct_scan_control_claim( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/control/claim' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array() ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$limits = ct_scan_control_limits();
	try {
		ct_scan_maintenance_locked();
		$busy = $wpdb->get_var( "SELECT job_id FROM {$table} WHERE status IN ('leased','running') OR (status = 'awaiting_control' AND control_state = 'checking') LIMIT 1" );
		if ( $busy ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'awaiting_control' AND control_state = 'requested' ORDER BY job_id ASC LIMIT 1" );
		if ( ! $row ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		if ( ! ct_scan_authorization_is_live( $row ) || empty( $row->confirmed_at ) || ! in_array( $row->control_requested_method, array( 'dns_txt', 'https_file' ), true ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none' ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$lease       = bin2hex( random_bytes( 32 ) );
		$expiry      = strtotime( $row->authorization_expires_at . ' UTC' );
		$lease_until = min( time() + $limits['lease_seconds'], $expiry );
		if ( $lease_until <= time() ) {
			return ct_scan_rest_response( 200, array( 'task' => null ) );
		}
		$updated = $wpdb->update(
			$table,
			array( 'control_state' => 'checking', 'control_lease_hash' => hash( 'sha256', $lease ), 'control_lease_until' => gmdate( 'Y-m-d H:i:s', $lease_until ), 'control_leased_ms' => (int) floor( microtime( true ) * 1000 ), 'control_admitted' => 0 ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'requested' ),
			array( '%s', '%s', '%s', '%d', '%d' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 503, 'claim_race' );
		}
		return ct_scan_rest_response( 200, array(
			'task' => array(
				'id'          => (int) $row->job_id,
				'target'      => $row->target_origin,
				'scope_hash'  => $row->scope_hash,
				'method'      => $row->control_requested_method,
				'expires_at'  => (int) $expiry,
				'lease'       => $lease,
				'lease_until' => (int) $lease_until,
			),
		) );
	} finally {
		ct_scan_lock_release();
	}
}

/** Does an observed value show the challenge? Only hashes of the token are stored. */
function ct_scan_control_value_matches( $method, $value, $token_hash ) {
	$limits = ct_scan_control_limits();
	if ( ! is_string( $value ) || ! is_string( $token_hash ) ) {
		return false;
	}
	if ( 'dns_txt' === $method ) {
		$prefix = $limits['dns_prefix'];
		if ( 0 !== strpos( $value, $prefix ) ) {
			return false;
		}
		$token = substr( $value, strlen( $prefix ) );
	} else {
		// Editors on some systems save a UTF-8 byte-order mark first; it is not part of the value.
		if ( 0 === strncmp( $value, "\xEF\xBB\xBF", 3 ) ) {
			$value = substr( $value, 3 );
		}
		$token = trim( $value, " \t\r\n" );
	}
	return 1 === preg_match( '/\A[a-f0-9]{64}\z/', $token ) && hash_equals( $token_hash, hash( 'sha256', $token ) );
}

/** Worker: report the outcome of the one admitted control request. */
function ct_scan_control_result( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/control/result' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	$limits = ct_scan_control_limits();
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash', 'method', 'outcome', 'observed' ) ) || ! ct_scan_callback_payload( $data )
		|| ! in_array( $data['method'], array( 'dns_txt', 'https_file' ), true ) || ! in_array( $data['outcome'], array( 'observed', 'not_found', 'error' ), true )
		|| ! is_array( $data['observed'] ) || ! ct_scan_is_list( $data['observed'] ) || count( $data['observed'] ) > 8 ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$total = 0;
	foreach ( $data['observed'] as $value ) {
		if ( ! is_string( $value ) || strlen( $value ) > $limits['max_bytes'] ) {
			return ct_scan_rest_error( 400, 'request_invalid' );
		}
		$total += strlen( $value );
	}
	if ( $total > $limits['max_bytes'] || ( 'observed' !== $data['outcome'] && array() !== $data['observed'] ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row || 'awaiting_control' !== $row->status || 'checking' !== $row->control_state || empty( $row->control_lease_hash )
			|| ! hash_equals( $row->control_lease_hash, hash( 'sha256', $data['lease'] ) ) || ! hash_equals( $row->scope_hash, $data['scope_hash'] )
			|| strtotime( $row->control_lease_until . ' UTC' ) <= time() || $row->control_requested_method !== $data['method'] ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		// The result of a check counts only if the guard admitted that check under this lease.
		if ( empty( $row->control_admitted ) || null === $row->control_last_attempt_ms || null === $row->control_leased_ms || (int) $row->control_last_attempt_ms < (int) $row->control_leased_ms ) {
			return ct_scan_rest_error( 409, 'no_admission' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null ), array( 'job_id' => (int) $row->job_id ), null, array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		$matched = '';
		if ( 'observed' === $data['outcome'] ) {
			foreach ( $data['observed'] as $value ) {
				if ( ct_scan_control_value_matches( $data['method'], $value, (string) $row->control_token_hash ) ) {
					$matched = $value;
					break;
				}
			}
		}
		$now = ct_scan_utc_now();
		if ( '' !== $matched ) {
			$evidence = wp_json_encode( array(
				'method'          => $data['method'],
				'attempt'         => (int) $row->control_attempts,
				'checked_at'      => $now,
				'target'          => $row->target_origin,
				'observed_sha256' => hash( 'sha256', $matched ),
			), JSON_UNESCAPED_SLASHES );
			$update = array( 'status' => 'queued', 'control_state' => 'none', 'control_method' => $data['method'], 'control_verified_at' => $now, 'control_valid_until' => $row->authorization_expires_at, 'control_evidence' => $evidence, 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null );
			$state  = 'queued';
		} elseif ( (int) $row->control_attempts >= $limits['max_attempts'] ) {
			$update = array( 'status' => 'blocked', 'error_code' => 'target_control_failed', 'finished_at' => $now, 'control_state' => 'none', 'control_token_hash' => null, 'control_page_hash' => null, 'control_lease_hash' => null, 'control_lease_until' => null, 'control_evidence' => wp_json_encode( array( 'method' => $data['method'], 'attempt' => (int) $row->control_attempts, 'last_outcome' => $data['outcome'] ) ) );
			$state  = 'blocked';
		} else {
			$update = array( 'control_state' => 'pending', 'control_lease_hash' => null, 'control_lease_until' => null, 'control_evidence' => wp_json_encode( array( 'method' => $data['method'], 'attempt' => (int) $row->control_attempts, 'last_outcome' => $data['outcome'] ) ) );
			$state  = 'awaiting_control';
		}
		$updated = $wpdb->update(
			$table,
			$update,
			array( 'job_id' => (int) $row->job_id, 'status' => 'awaiting_control', 'control_state' => 'checking', 'control_lease_hash' => $row->control_lease_hash ),
			array_fill( 0, count( $update ), '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'result_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, $state, 'blocked' === $state ? 'target_control_failed' : '' );
		return ct_scan_rest_response( 200, array( 'ok' => true, 'verified' => '' !== $matched ) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_register_rest_routes() {
	register_rest_route( 'ct-scan/v1', '/claim', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_claim',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/start', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_start',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/admit', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_admit',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/control/claim', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_control_claim',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/control/result', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_control_result',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/result', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_result',
		'permission_callback' => '__return_true',
	) );
}
add_action( 'rest_api_init', 'ct_scan_register_rest_routes' );

function ct_scan_terminal_status( $status ) {
	return in_array( $status, ct_scan_terminal_statuses(), true );
}

function ct_scan_email_safe_text( $value, $max = 2000 ) {
	if ( ! is_string( $value ) ) {
		return '';
	}
	$value = wp_strip_all_tags( $value );
	$value = preg_replace( '/https?:\/\/[^\s<>"\']+/i', '[URL omitted]', $value );
	$value = preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+/', ' ', $value );
	$value = preg_replace( '/[ \t]+/', ' ', $value );
	$value = preg_replace( '/\n{3,}/', "\n\n", $value );
	return substr( trim( $value ), 0, $max );
}

function ct_scan_build_report_body( $row ) {
	if ( ! is_object( $row ) || ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status || '' === trim( (string) $row->manual_remainder_notes ) ) {
		return new WP_Error( 'report_not_ready', 'The scan and manual remainder are not ready for a reviewed report.' );
	}
	$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
	if ( ! is_string( $host ) || '' === $host ) {
		return new WP_Error( 'report_target_invalid', 'The saved target could not be verified.' );
	}
	$lines = array(
		'PHP2Shell passive screening and manual review',
		'Authorized target host: ' . $host,
		'Terms version: ' . $row->terms_version,
		'Terms accepted (UTC): ' . $row->terms_accepted_at,
		'',
		'PHP2Shell passive screening',
	);
	if ( 'completed' === $row->status ) {
		if ( ! is_string( $row->result_json ) || '' === $row->result_json ) {
			return new WP_Error( 'report_result_missing', 'The stored PHP2Shell result is unavailable.' );
		}
		$result = json_decode( $row->result_json, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$validated = ct_scan_validate_result( $result, $row, true );
		if ( is_wp_error( $validated ) ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$labels = array(
			'potentially_affected'   => 'Potentially affected: an advertised PHP version is below an upstream fix threshold; an administrator should verify the actual package and vendor backports.',
			'fixed_version_reported' => 'Fixed version reported: the public advertisement meets an upstream threshold; this does not verify the running package or prove safety.',
			'unknown'               => 'Unknown: public evidence did not support a reliable version classification.',
		);
		$lines[] = 'Screen status: ' . $labels[ $result['php2shell_status'] ];
		$lines[] = 'WordPress detection: ' . $result['status'];
		$lines[] = 'Fetch status: ' . $result['fetch_status'];
		$lines[] = 'HTTP status: ' . ( null === $result['http_status'] ? 'unavailable' : (string) $result['http_status'] );
		$lines[] = 'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : ct_scan_email_safe_text( $result['php_version'], 128 ) );
		$lines[] = 'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available for this advertised version' : $result['php2shell_fixed_version'] );
		$lines[] = 'PHP2Shell rules date: ' . $result['php2shell_rules_as_of'];
		$lines[] = 'Exploitability: not tested; no exploit payloads were sent.';
		$lines[] = 'Limit: this passive screen reads public robots policy, page content, and headers. It cannot verify the deployed runtime, vendor backports, or patch state.';
		$evidence = array_slice( $result['php_evidence'], 0, 10 );
		if ( $evidence ) {
			$lines[] = 'Observed PHP-related header evidence:';
			foreach ( $evidence as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 500 );
			}
		}
		$notes = array_slice( $result['php2shell_notes'], 0, 10 );
		if ( $notes ) {
			$lines[] = 'Interpretation notes:';
			foreach ( $notes as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 1000 );
			}
		}
	} else {
		$lines[] = 'No PHP2Shell classification was produced.';
		$lines[] = 'Execution state: ' . $row->status . ( $row->error_code ? ' (' . sanitize_key( $row->error_code ) . ')' : '' );
		$lines[] = 'No rescan was started while preparing this report.';
	}
	$lines[] = '';
	$lines[] = 'Other checks in the accepted service terms (manual remainder)';
	$lines[] = ct_scan_email_safe_text( $row->manual_remainder_notes, 12000 );
	$lines[] = '';
	$lines[] = 'This report is limited to the evidence above. It does not establish confirmed exploitation or a verified clean bill of health.';
	return implode( "\n", $lines ) . "\n";
}

function ct_scan_admin_revoke( $job_id ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->report_delivered_at ) ) {
			return new WP_Error( 'job_unavailable', 'This job cannot be revoked.' );
		}
		$now = ct_scan_utc_now();
		$update = array( 'revoked_at' => $now, 'confirmation_token_hash' => null, 'lease_hash' => null, 'lease_until' => null, 'control_token_hash' => null, 'control_page_hash' => null, 'control_state' => 'none', 'control_lease_hash' => null, 'control_lease_until' => null );
		if ( ! ct_scan_terminal_status( $row->status ) ) {
			$update['status'] = 'cancelled';
			$update['error_code'] = 'operator_revoked';
			$update['finished_at'] = $now;
		}
		$updated = $wpdb->update( $table, $update, array( 'job_id' => (int) $row->job_id, 'status' => $row->status, 'report_delivered_at' => null ), null, array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'revoke_write_failed', 'The authorization state could not be durably updated. No success was recorded.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, ct_scan_terminal_status( $row->status ) ? $row->status : 'cancelled', 'operator_revoked' );
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_save_manual_remainder( $job_id, $notes ) {
	if ( ! is_string( $notes ) ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter the completed manual review notes.' );
	}
	$notes = trim( sanitize_textarea_field( wp_unslash( $notes ) ) );
	if ( '' === $notes || strlen( $notes ) > 12000 ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter manual review notes of 1 to 12,000 characters.' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! ct_scan_terminal_status( $row->status ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'manual_review_not_ready', 'Manual completion is available only after the scan is terminal and before revocation or delivery.' );
		}
		$updated = $wpdb->update( $table, array( 'manual_remainder_status' => 'complete', 'manual_remainder_notes' => $notes, 'manual_remainder_completed_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null, 'revoked_at' => null ), array( '%s', '%s', '%s' ), array( '%d', '%s', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'manual_review_write_failed', 'The manual review could not be durably saved.' );
		}
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_send_report( $job_id ) {
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'report_send_unavailable', 'This report cannot be sent in its current state.' );
		}
		if ( ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status
			|| '' === trim( (string) $row->manual_remainder_notes ) ) {
			return new WP_Error( 'report_not_ready', 'Complete and review the manual remainder before sending.' );
		}
		// Detailed findings go only to a recipient who confirmed the request, whatever the terminal state.
		if ( empty( $row->confirmed_at ) ) {
			return new WP_Error( 'report_recipient_unconfirmed', 'The recipient never confirmed this request. Detailed findings cannot be sent.' );
		}
		// ...and, when the job required it, only for a target whose control was established.
		if ( ct_scan_control_required( $row ) && empty( $row->control_verified_at ) ) {
			return new WP_Error( 'report_target_unverified', 'Control of the target was never established. Detailed findings cannot be sent.' );
		}
		if ( ! is_email( $row->contact_email )
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_email' ) !== $row->contact_email
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_version' ) !== $row->terms_version
			// The job stores the recorded terms hash lowercased (as the accepted-copy path compares it).
			|| strtolower( ct_scan_meta_string( (int) $row->request_id, '_ct_terms_sha256' ) ) !== $row->terms_hash ) {
			return new WP_Error( 'report_contact_changed', 'The original authorized report contact could not be verified.' );
		}
		$body = ct_scan_build_report_body( $row );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update(
			$table,
			array( 'report_notification_status' => 'unknown', 'report_notification_at' => $now ),
			array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null, 'revoked_at' => null ),
			array( '%s', '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_state_write_failed', 'The one-time send state could not be durably recorded. No email was sent.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', 'unknown' );
		$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
		$status = 'unknown';
		try {
			if ( wp_mail( $row->contact_email, 'Reviewed website screening report for ' . $host, $body ) ) {
				$status = 'accepted';
			}
		} catch ( Throwable $error ) {
			$status = 'unknown';
		}
		$updated = $wpdb->update( $table, array( 'report_notification_status' => $status, 'report_notification_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => 'unknown', 'report_delivered_at' => null ), array( '%s', '%s' ), array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_state_write_failed', 'The email outcome could not be durably recorded. Its status remains unknown; do not resend.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', $status );
	}
	finally {
		ct_scan_lock_release();
	}
	return 'accepted' === $status ? true : new WP_Error( 'report_transport_unknown', 'The mail transport did not confirm acceptance. Check delivery logs before attempting another send.' );
}

function ct_scan_admin_record_delivery( $job_id ) {
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! in_array( $row->report_notification_status, array( 'accepted', 'unknown' ), true ) || ! empty( $row->report_delivered_at ) ) {
			return new WP_Error( 'report_delivery_unverified', 'Record delivery only after independently confirming that the full report reached the saved contact.' );
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update( $table, array( 'report_delivered_at' => $now ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null ), array( '%s' ), array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_delivery_write_failed', 'The delivery confirmation could not be durably saved.' );
		}
		$cancelled = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET status = 'cancelled', error_code = 'report_delivered', finished_at = %s, lease_hash = NULL, lease_until = NULL, confirmation_token_hash = NULL WHERE job_id = %d AND status IN ('awaiting_confirmation','awaiting_control','queued','leased','running')", $now, (int) $row->job_id ) );
		if ( false === $cancelled ) {
			return new WP_Error( 'report_delivery_write_failed', 'Delivery was saved, but follow-up scan cancellation could not be confirmed.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_delivered_at', $now );
		ct_scan_mark_request_status( (int) $row->request_id, ct_scan_terminal_status( $row->status ) ? $row->status : 'cancelled', 'report_delivered' );
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_action_handler() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to manage scan requests.', 'ct-scan' ), '', array( 'response' => 403 ) );
	}
	$job_id = isset( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	$action = isset( $_POST['ct_scan_operation'] ) && is_string( $_POST['ct_scan_operation'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_operation'] ) ) : '';
	if ( ! $job_id || ! in_array( $action, array( 'revoke', 'manual_complete', 'send_report', 'record_delivery', 'authority_review', 'set_hold', 'release_hold' ), true ) ) {
		wp_die( esc_html__( 'The requested action is invalid.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	check_admin_referer( 'ct_scan_admin_' . $action . '_' . $job_id );
	$confirmations = array(
		'revoke'          => 'ct_scan_revoke_confirm',
		'manual_complete' => 'ct_scan_review_confirm',
		'send_report'     => 'ct_scan_send_confirm',
		'record_delivery' => 'ct_scan_delivery_confirm',
		'authority_review' => 'ct_scan_authority_confirm',
		'set_hold'        => 'ct_scan_hold_confirm',
		'release_hold'    => 'ct_scan_hold_release_confirm',
	);
	$confirm_key = $confirmations[ $action ];
	if ( ! isset( $_POST[ $confirm_key ] ) || ! is_string( $_POST[ $confirm_key ] ) || '1' !== wp_unslash( $_POST[ $confirm_key ] ) ) {
		wp_die( esc_html__( 'Confirm this action before continuing.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	if ( 'revoke' === $action ) {
		$result = ct_scan_admin_revoke( $job_id );
	} elseif ( 'manual_complete' === $action ) {
		$result = ct_scan_admin_save_manual_remainder( $job_id, isset( $_POST['manual_remainder_notes'] ) && is_string( $_POST['manual_remainder_notes'] ) ? $_POST['manual_remainder_notes'] : '' );
	} elseif ( 'send_report' === $action ) {
		$result = ct_scan_admin_send_report( $job_id );
	} elseif ( 'set_hold' === $action ) {
		$result = ct_scan_admin_set_hold( $job_id, isset( $_POST['ct_scan_hold_reason'] ) && is_string( $_POST['ct_scan_hold_reason'] ) ? wp_unslash( $_POST['ct_scan_hold_reason'] ) : '', isset( $_POST['ct_scan_hold_days'] ) && is_scalar( $_POST['ct_scan_hold_days'] ) ? wp_unslash( $_POST['ct_scan_hold_days'] ) : 0 );
	} elseif ( 'release_hold' === $action ) {
		$result = ct_scan_admin_release_hold( $job_id, isset( $_POST['ct_scan_hold_identity'] ) && is_string( $_POST['ct_scan_hold_identity'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_hold_identity'] ) ) : '' );
	} elseif ( 'authority_review' === $action ) {
		$result = ct_scan_admin_record_authority_review( $job_id, isset( $_POST['ct_scan_authority_note'] ) && is_string( $_POST['ct_scan_authority_note'] ) ? wp_unslash( $_POST['ct_scan_authority_note'] ) : '' );
	} else {
		$result = ct_scan_admin_record_delivery( $job_id );
	}
	$notice = is_wp_error( $result ) ? $result->get_error_code() : 'updated';
	$url = add_query_arg( array( 'page' => 'ct-scan-queue', 'ct_scan_notice' => sanitize_key( $notice ) ), admin_url( 'edit.php?post_type=ct_promo_request' ) );
	wp_safe_redirect( $url );
	exit;
}
add_action( 'admin_post_ct_scan_admin_action', 'ct_scan_admin_action_handler' );

function ct_scan_admin_form( $job_id, $operation, $label, $extra = '' ) {
	$nonce = wp_nonce_field( 'ct_scan_admin_' . $operation . '_' . $job_id, '_wpnonce', true, false );
	return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:4px 8px 4px 0"><input type="hidden" name="action" value="ct_scan_admin_action"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="ct_scan_operation" value="' . esc_attr( $operation ) . '">' . $nonce . $extra . '<button class="button" type="submit">' . esc_html( $label ) . '</button></form>';
}

/** One line summarizing a recorded manual authority review, for the admin queue. */
function ct_scan_control_evidence_line( $row ) {
	$evidence = json_decode( (string) $row->control_evidence, true );
	if ( ! is_array( $evidence ) ) {
		return 'unreadable';
	}
	return sprintf( '%s at %s UTC, valid until %s UTC: %s', (string) ( $evidence['reviewer'] ?? '?' ), (string) ( $evidence['reviewed_at'] ?? '?' ), (string) ( $evidence['valid_until'] ?? '?' ), (string) ( $evidence['evidence'] ?? '' ) );
}

function ct_scan_admin_result_details( $row ) {
	if ( ! is_object( $row ) || 'completed' !== $row->status || ! is_string( $row->result_json ) || '' === $row->result_json ) {
		return '';
	}
	$result = json_decode( $row->result_json, true );
	if ( JSON_ERROR_NONE !== json_last_error() || is_wp_error( ct_scan_validate_result( $result, $row, true ) ) ) {
		return '<p>Stored result failed its integrity and schema check.</p>';
	}
	$lines = array(
		'PHP2Shell status: ' . $result['php2shell_status'],
		'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : $result['php_version'] ),
		'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available' : $result['php2shell_fixed_version'] ),
		'Rules date: ' . $result['php2shell_rules_as_of'],
		'Exploitability: not tested; no exploit payloads were sent.',
	);
	$html = '<details><summary>Private stored PHP2Shell evidence and summary</summary><pre>' . esc_html( implode( "\n", $lines ) ) . '</pre>';
	foreach ( array( 'php_evidence' => 'Observed PHP evidence', 'php2shell_notes' => 'Assessment notes', 'php2shell_sources' => 'Assessment sources' ) as $key => $label ) {
		if ( empty( $result[ $key ] ) ) {
			continue;
		}
		$html .= '<p><strong>' . esc_html( $label ) . '</strong></p><ul>';
		foreach ( array_slice( $result[ $key ], 0, 20 ) as $entry ) {
			$html .= '<li><code>' . esc_html( $entry ) . '</code></li>';
		}
		$html .= '</ul>';
	}
	if ( '' !== $result['php2shell_recommendation'] ) {
		$html .= '<p><strong>Recommendation:</strong> ' . esc_html( $result['php2shell_recommendation'] ) . '</p>';
	}
	return $html . '</details>';
}

function ct_scan_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	ct_scan_maintain();
	global $wpdb;
	$table = ct_scan_jobs_table();
	$rows  = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC, job_id DESC LIMIT 100" );
	$config = ct_scan_config();
	echo '<div class="wrap"><h1>PHP2Shell screening queue</h1>';
	echo '<p>Worker API: <strong>' . ( ct_scan_enabled() ? 'enabled' : 'disabled' ) . '</strong>. This page never displays the worker secret. The screening covers public passive evidence only; broader checks remain manual.</p>';
	if ( isset( $_GET['ct_scan_notice'] ) && is_string( $_GET['ct_scan_notice'] ) ) {
		$notice   = sanitize_key( wp_unslash( $_GET['ct_scan_notice'] ) );
		$messages = array(
			'hold_active'  => 'Not changed: this job already has a preservation hold. A second hold cannot replace or shorten it; release the existing hold first (the records stay protected through the grace period), then place the new one.',
			'hold_changed' => 'Not changed: the hold was modified since this page was loaded (for example, released and replaced by another administrator). Reload the queue to see the current hold, then try again.',
		);
		echo '<div class="notice notice-info"><p>' . esc_html( $messages[ $notice ] ?? $notice ) . '</p></div>';
	}
	if ( empty( $rows ) ) {
		echo '<p>No screening jobs are stored.</p></div>';
		return;
	}
	echo '<table class="widefat striped"><thead><tr><th>Job / request</th><th>Authorized scope and terms</th><th>Execution</th><th>Confirmation / report</th><th>Manual remainder and actions</th></tr></thead><tbody>';
	foreach ( $rows as $row ) {
		$request_url = admin_url( 'post.php?post=' . (int) $row->request_id . '&action=edit' );
		$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
		$exec = 'Status: ' . $row->status . "\nAttempts: " . (int) $row->attempts . "\nOutcome: " . ( $row->outcome ? $row->outcome : 'pending' ) . "\nTarget control: " . ( $row->control_required ? ( $row->control_verified_at ? sanitize_key( (string) $row->control_method ) . ' at ' . $row->control_verified_at . ' UTC' : 'required, not shown (' . (int) $row->control_attempts . ' of 3 checks used)' ) : 'not required' ) . "\nClosed: " . ( $row->closed_at ? $row->closed_at . ' UTC' : '—' ) . "\nEvidence deletion date: " . ( $row->retain_until ? $row->retain_until . ' UTC' : ( $row->closed_at ? 'unknown (kept)' : '—' ) ) . "\nError: " . ( $row->error_code ? sanitize_key( $row->error_code ) : '—' ) . ( 'manual_review' === $row->control_method ? "\nAuthority review: " . ct_scan_control_evidence_line( $row ) : '' ) . "\nChecker revision: " . ( $row->checker_revision ? substr( $row->checker_revision, 0, 12 ) . '…' : '—' );
		$mail = 'Confirmation email: ' . sanitize_key( $row->confirmation_email_status ) . "\nReport transport: " . sanitize_key( $row->report_notification_status ) . "\nDelivery confirmed: " . ( $row->report_delivered_at ? $row->report_delivered_at . ' UTC' : 'no' ) . "\nRevoked: " . ( $row->revoked_at ? $row->revoked_at . ' UTC' : 'no' );
		echo '<tr><td><a href="' . esc_url( $request_url ) . '">Job #' . (int) $row->job_id . ' / request #' . (int) $row->request_id . '</a><br>Created ' . esc_html( $row->created_at ) . ' UTC</td>';
		echo '<td><code>' . esc_html( $row->target_origin ) . '</code><br>Terms ' . esc_html( $row->terms_version ) . '<br>Accepted ' . esc_html( $row->terms_accepted_at ) . ' UTC<br>Expires ' . esc_html( $row->authorization_expires_at ) . ' UTC<br>Scope hash <code>' . esc_html( substr( $row->scope_hash, 0, 16 ) ) . '…</code></td>';
		echo '<td><pre>' . esc_html( $exec ) . '</pre>' . ct_scan_admin_result_details( $row ) . '</td><td><pre>' . esc_html( $mail ) . '</pre></td><td>';
		if ( ! empty( $row->manual_remainder_notes ) ) {
			echo '<details><summary>Manual remainder (' . esc_html( sanitize_key( $row->manual_remainder_status ) ) . ')</summary><pre>' . esc_html( $row->manual_remainder_notes ) . '</pre></details>';
		}
		if ( ct_scan_terminal_status( $row->status ) && empty( $row->revoked_at ) && empty( $row->report_delivered_at ) ) {
			$notes = esc_textarea( (string) $row->manual_remainder_notes );
			$extra = '<br><textarea name="manual_remainder_notes" rows="4" cols="42" maxlength="12000" placeholder="Record the remaining checks covered by the accepted service terms, including limitations or why any check was not completed.">' . $notes . '</textarea><br><label><input type="checkbox" name="ct_scan_review_confirm" value="1" required> I reviewed these manual findings and limitations.</label> ';
			echo ct_scan_admin_form( (int) $row->job_id, 'manual_complete', 'Save manual remainder', $extra );
			$preview = ct_scan_build_report_body( $row );
			if ( ! is_wp_error( $preview ) ) {
				echo '<details><summary>Reviewed customer report preview</summary><pre>' . esc_html( $preview ) . '</pre></details>';
				if ( 'not_sent' === $row->report_notification_status || 'failed' === $row->report_notification_status ) {
					echo ct_scan_admin_form( (int) $row->job_id, 'send_report', 'Send reviewed report to stored contact', '<label><input type="checkbox" name="ct_scan_send_confirm" value="1" required> Send this report to the saved authorized email contact.</label> ' );
				}
			}
			if ( in_array( $row->report_notification_status, array( 'accepted', 'unknown' ), true ) && empty( $row->report_delivered_at ) ) {
				echo ct_scan_admin_form( (int) $row->job_id, 'record_delivery', 'Record confirmed delivery', '<label><input type="checkbox" name="ct_scan_delivery_confirm" value="1" required> I independently confirmed the full report reached the saved contact.</label> ' );
			}
		}
		if ( 'awaiting_control' === $row->status && empty( $row->revoked_at ) ) {
			echo ct_scan_admin_form( (int) $row->job_id, 'authority_review', 'Record authority review', '<br><textarea name="ct_scan_authority_note" rows="3" cols="42" maxlength="1000" placeholder="Evidence reviewed that this client controls this exact website (who, what, when)."></textarea><br><label><input type="checkbox" name="ct_scan_authority_confirm" value="1" required> I reviewed evidence that this client controls the exact website above.</label> ' );
		}
		$on_hold = ct_scan_job_on_hold( $row, ct_scan_utc_now() );
		if ( $on_hold && empty( $row->hold_released_at ) ) {
			echo '<p>Preservation hold until ' . esc_html( $row->hold_until ) . ' UTC: ' . esc_html( $row->hold_reason ) . '</p>' . ct_scan_admin_form( (int) $row->job_id, 'release_hold', 'Release hold', '<input type="hidden" name="ct_scan_hold_identity" value="' . esc_attr( ct_scan_hold_identity( $row ) ) . '"><label><input type="checkbox" name="ct_scan_hold_release_confirm" value="1" required> Release this hold.</label> ' );
		} else {
			if ( $on_hold ) {
				// Released, still inside the grace period: show it, and allow a new hold.
				echo '<p>Preservation hold released ' . esc_html( $row->hold_released_at ) . ' UTC (records kept for a further ' . (int) ct_scan_hold_grace_days() . ' days): ' . esc_html( $row->hold_reason ) . '</p>';
			}
			echo ct_scan_admin_form( (int) $row->job_id, 'set_hold', 'Place preservation hold', '<br><input type="text" name="ct_scan_hold_reason" maxlength="190" size="40" placeholder="Narrow purpose, e.g. dispute #123 about this job"> <input type="number" name="ct_scan_hold_days" min="1" max="730" value="90"> days<br><label><input type="checkbox" name="ct_scan_hold_confirm" value="1" required> Preserve this job\'s records for this stated purpose only.</label> ' );
		}
		if ( empty( $row->revoked_at ) && empty( $row->report_delivered_at ) ) {
			echo ct_scan_admin_form( (int) $row->job_id, 'revoke', 'Revoke authorization', '<label><input type="checkbox" name="ct_scan_revoke_confirm" value="1" required> Revoke this request and block further execution or report sending.</label> ' );
		}
		echo '</td></tr>';
	}
	echo '</tbody></table></div>';
}

function ct_scan_register_admin_menu() {
	add_submenu_page( 'edit.php?post_type=ct_promo_request', 'PHP2Shell screening queue', 'PHP2Shell queue', 'manage_options', 'ct-scan-queue', 'ct_scan_admin_page' );
}
add_action( 'admin_menu', 'ct_scan_register_admin_menu', 30 );

function ct_scan_add_request_meta_box() {
	add_meta_box( 'ct-scan-request-status', 'PHP2Shell screening', 'ct_scan_request_meta_box', 'ct_promo_request', 'side', 'high' );
}
add_action( 'add_meta_boxes_ct_promo_request', 'ct_scan_add_request_meta_box' );

function ct_scan_request_meta_box( $post ) {
	$job_id = absint( get_post_meta( $post->ID, '_ct_scan_job_id', true ) );
	$row = $job_id ? ct_scan_row( $job_id ) : null;
	if ( ! $row ) {
		echo '<p>No scan job is linked to this request.</p>';
		return;
	}
	echo '<p>Status: <strong>' . esc_html( $row->status ) . '</strong></p><p>Target: <code>' . esc_html( $row->target_origin ) . '</code></p><p>Terms: ' . esc_html( $row->terms_version ) . ' / <code>' . esc_html( substr( $row->terms_hash, 0, 16 ) ) . '…</code></p><p>Confirmation email: ' . esc_html( $row->confirmation_email_status ) . '</p><p>Attempts: ' . (int) $row->attempts . ' · report transport: ' . esc_html( $row->report_notification_status ) . '</p><p><a href="' . esc_url( admin_url( 'edit.php?post_type=ct_promo_request&page=ct-scan-queue' ) ) . '">Open private queue</a></p>';
}
