# PHP2Shell assessment methodology

This tool performs passive version-based triage for **CVE-2026-109618** and
**CVE-2026-109619**, using a rule snapshot checked on **2026-10-21**.

## Sources and scope

The PHP project lists fixes in 8.2.35, 8.3.36, 8.4.27, and 8.5.12 in its
[first advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [second advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
The linked [Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
provides background; the classifier takes its version thresholds from PHP's
published advisories, rather than pre-release estimates.

The conditions depend on the PHP runtime interface and request handling. For
example, the PHP advisories distinguish mod_php from conditional FPM exposure.
An `Apache`, `nginx`, `LiteSpeed`, or `cloudflare` header alone cannot establish
those conditions. This script therefore does not assign a SAPI or claim RCE.

## How a decision is made

1. Inspect only the headers already returned by the normal page request.
2. Collect complete `PHP/version` tokens from `X-Powered-By` and `Server`.
3. Preserve all distinct versions. Conflicting tokens yield `unknown`.
4. Compare a complete, unqualified release with the fix in the **same branch**.
5. Include the decision reason, fix threshold, sources, and rule date in output.

| `php2shell_version_status` | Interpretation |
| --- | --- |
| `below_upstream_fix` | Bare release below its branch's threshold; `potentially_affected`. |
| `at_or_above_upstream_fix` | Bare release meets threshold; `fixed_version_reported`. |
| `version_not_disclosed` | PHP version unavailable; `unknown`. |
| `conflicting_versions` | More than one distinct PHP version advertised; `unknown`. |
| `unrecognized_or_partial_version` | Cannot compare the token safely; `unknown`. |
| `prerelease_unverified` | Development/alpha/beta/RC qualifier; `unknown`. |
| `vendor_build_unverified` | Vendor/build qualifier; `unknown`. |
| `branch_requires_vendor_review` | Outside the 8.2–8.5 rule table; `unknown`. |

All results set `php2shell_exploitability` to **`not_tested`**. A WordPress
version, theme version, asset cache key, or missing PHP header cannot determine
PHP2Shell patch status. WordPress is not required for PHP2Shell triage.

## Backports and hidden package information

[Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) documents
vendor fixes with upstream bases older than PHP's new releases. A bare header
can omit this package information. Even `potentially_affected` requires the
administrator to verify the actual package, vendor advisory, deployed workers,
and runtime configuration. No status here certifies that a site is vulnerable
or free of vulnerabilities.

## Offline use

```python
from wordpress_check import assess_php2shell

result = assess_php2shell("8.3.35")
assert result["php2shell_status"] == "potentially_affected"
assert result["php2shell_exploitability"] == "not_tested"
```

This function performs no network requests. Website checks also add no new
requests for the assessment: no crafted bodies, multipart uploads, memory
pressure, worker-reuse tests, command execution, or guessed diagnostic URLs.
Existing robots and access checks still apply.

## Updating the rules

Review the official advisories before changing `PHP2SHELL_FIXES` or the rule
date. Add boundary and vendor-qualification tests with any change. A new branch
does not automatically inherit a safe classification. Keep real target lists,
contact details, and scan outputs out of the repository.
