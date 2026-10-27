<?php
/** Test helper: one maintenance pass (state transitions, then retention) under the environment's retention config. */
require __DIR__ . '/support.php';
ct_scan_maintenance_locked();
echo ct_scan_retention_run( true ) ? "maintained\n" : "retention did not run\n";
