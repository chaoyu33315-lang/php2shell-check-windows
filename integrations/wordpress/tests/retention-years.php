<?php
/** Prints the evidence deletion date computed for a non-legacy and a legacy row under the environment's retention config. */
require __DIR__ . '/support.php';
$row = (object) array( 'terms_version' => '2027-06-01-r3', 'closed_at' => '2026-01-01 00:00:00', 'terms_accepted_at' => '2025-01-01 00:00:00' );
$old = (object) array( 'terms_version' => '2026-10-21-r2', 'closed_at' => '2026-01-01 00:00:00', 'terms_accepted_at' => '2025-01-01 00:00:00' );
echo ct_scan_retain_until( $row ) . ' ' . ct_scan_retain_until( $old ) . "\n";
