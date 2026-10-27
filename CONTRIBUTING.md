# Contributing

Open an issue for bugs or focused improvements, then submit a pull request.
For a security issue in the checker, use the process in [SECURITY.md](SECURITY.md).

## Local development

Python 3.10+ is sufficient; there are no runtime or test dependencies.

```sh
python -m unittest -v
python wordpress_check.py --help
```

Keep the checker usable as one Python file. Changes must preserve its public-page
scope, TLS verification, robots checks, descriptive User-Agent, request limits,
and explicit uncertainty. Do not turn an absent marker or a version disclosure
into an unsupported vulnerability claim.

PHP2Shell rules must cite official advisories and include branch-specific
boundary tests. Keep build qualifiers and vendor-backport uncertainty intact.
The assessment must not add HTTP requests or exploit payloads.

Add focused regression tests for behavior changes. Prefer local HTTP fixtures
and mocks; automated tests must not contact external websites. If a case depends
on a real response, reduce it to a small, synthetic fixture without personal
data, tokens, cookies, or private URLs.

Document changes to command arguments and output fields. Run the tests before
submitting a pull request. Never include real outreach lists, workbooks, scan
results, or credentials in a contribution.

## Licensing of contributions

php2shell-check is dual licensed under AGPL-3.0 and a CompleteTech LLC
commercial license (see [LICENSING.md](LICENSING.md)). By submitting a
contribution, you confirm that you have the right to submit it. You license
it to the public under AGPL-3.0. You also grant CompleteTech LLC a perpetual,
worldwide, royalty-free, irrevocable license to use, modify, sublicense and
distribute it under any license, including the commercial license. You keep
the copyright in your contribution.
