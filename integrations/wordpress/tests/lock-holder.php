<?php
/** Test helper: hold the queue lock for N seconds, simulating an admission in progress. */
require __DIR__ . '/support.php';
$seconds = isset( $argv[1] ) ? max( 0.1, min( 5, (float) $argv[1] ) ) : 1.0;
$retention = isset( $argv[2] ) && 'retention' === $argv[2];
if ( ! ( $retention ? ct_scan_retention_lock_acquire() : ct_scan_lock_acquire() ) ) {
	fwrite( STDOUT, "busy\n" );
	exit( 1 );
}
fwrite( STDOUT, "locked\n" );
fflush( STDOUT );
usleep( (int) ( $seconds * 1000000 ) );
if ( $retention ) {
	ct_scan_retention_lock_release();
} else {
	ct_scan_lock_release();
}
