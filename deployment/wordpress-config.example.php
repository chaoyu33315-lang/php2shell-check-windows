<?php
// Copy into the HTTP-denied wp-content/ct-scan-private/config.php directory.
// The adjacent worker.key must contain the same random key as the worker volume.
// Never put either deployed file in source control.
return array(
    // Keep false until EVERY item in docs/WORDPRESS.md "Egress" and the site's activation checklist is done.
    'enabled' => false,
    // Set true only after outbound traffic from the worker is restricted by something the scanner
    // cannot change (see deployment/egress-filter.nft.example). While false the integration refuses to enable.
    'egress_enforced' => false,
    'supported_terms_version' => '2026-10-21-r2',
    // REQUIRED explicit decision for the version above, or the integration refuses to enable:
    //   'strict' : bound evidence (and target control) required - what every new version must use;
    //   'legacy' : grandfathers the existing r2-or-earlier flow; honoured ONLY for r2-or-earlier versions.
    // Bumping supported_terms_version without adding its entry disables the integration.
    'terms_policy' => array('2026-10-21-r2' => 'legacy'),
    'expected_checker_revision' => 'REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT_SHA',
    'expected_rules_as_of' => '2026-10-21',
    'worker_hmac_secret' => is_readable(__DIR__ . '/worker.key')
        ? trim(file_get_contents(__DIR__ . '/worker.key')) : '',
    'authorization_end_at' => '2026-12-20T23:59:59Z',
    'confirmation_ttl_hours' => 168,
    'global_daily_limit' => 20,
    'target_daily_limit' => 1,
);
