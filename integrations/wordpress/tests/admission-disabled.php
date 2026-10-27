<?php
/** Run with CT_TEST_ENABLED=0: the global kill switch must refuse every admission. */
require __DIR__ . '/support.php';
ct_test_assert( ! ct_scan_enabled(), 'Fixture expected the integration to be disabled.' );
$response = ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', array( 'id' => 1, 'lease' => str_repeat( 'a', 64 ), 'scope_hash' => str_repeat( 'b', 64 ), 'kind' => 'http' ) );
ct_test_assert( 503 === $response->get_status() && 'ct_scan_disabled' === ( $response->get_data()['error'] ?? '' ), 'A disabled integration admitted or mis-reported a request.' );
echo "disabled\n";
