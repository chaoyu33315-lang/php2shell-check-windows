<?php
/** Prints whether the integration is enabled under the environment-selected configuration, and the policy of the served version. */
require __DIR__ . '/support.php';
echo ( ct_scan_enabled() ? 'enabled' : 'refused' ) . ' ' . ct_scan_terms_policy( ct_scan_config()['supported_terms_version'] ) . "\n";
