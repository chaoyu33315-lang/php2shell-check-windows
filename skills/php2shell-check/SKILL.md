---
name: php2shell-check
description: Use php2shell-check for passive PHP2Shell exposure triage of authorized websites, interpret advertised PHP versions and WordPress markers, and produce CSV, JSON, or HTML reports. Use for running or interpreting this checker, not exploit testing or server patching.
---

# PHP2Shell Check Windows

Use the dependency-free `wordpress_check.py` CLI from
[CompleteTech-LLC/php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check).
It compares advertised PHP versions with an embedded, dated rule snapshot;
it does not establish exploitability. WordPress is not required for the check.

## Locate the checker

This skill contains instructions, not a bundled copy of the scanner. Use the
user's existing checkout or standalone `wordpress_check.py` when available.
Otherwise clone the repository into a new local directory:

```sh
git clone https://github.com/CompleteTech-LLC/php2shell-check.git
cd php2shell-check
python --version
python wordpress_check.py --help
```

Python 3.10+ is required; substitute `python3` where appropriate. No pip package,
API key, or browser is needed. Run the examples from the checker directory, or
use its absolute script path. Do not assume an installed skill's parent directory
contains the checker. Record the checkout revision when available and retain
`php2shell_rules_as_of` and `php2shell_sources` from the results. The rule table
does not refresh automatically.

For additional options, use the checkout's `--help` and `docs/REFERENCE.md`;
for classification details, read `docs/PHP2SHELL.md`. If only the standalone
script is available, consult the same files in the upstream repository at the
matching revision when known.

## Select scope and inputs

- Use only targets covered by the user's authorized assessment. Reuse clear
  existing authorization; ask only if scope or permission is genuinely missing.
  A permissive or missing robots.txt is not authorization.
- The checker fetches robots.txt and the supplied page, following up to five
  page redirects and checking destination robots policies. It can follow
  redirects to other hosts and accepts local/private addresses; it has no host
  allowlist option. If a strict host boundary is required, use an appropriately
  restricted network environment or offline evidence instead of assuming the
  CLI enforces that boundary.
- Pass explicit HTTP(S) URLs or bare domains (which default to HTTPS). For a
  batch, prepare UTF-8 text with one target per line. Blank lines and full-line
  `#` comments are ignored; a BOM is accepted. Exact duplicates are skipped.
  `--input` does not read CSV or Excel: extract only the authorized URL column
  into a separate text file first. Do not include credentials or secret tokens.
- Keep the existing TLS checks, honest User-Agent, robots rules, and sequential
  pacing. Do not bypass restrictions, probe guessed admin/PHP-info endpoints,
  send exploit payloads, or add retries to get around a block.

## Run and preserve the output

Choose a new output path outside version control; create its parent directory
first. `--output` overwrites an existing file. The following paths and domains
are examples: replace them with the authorized inputs and chosen output paths,
and do not scan example domains as a test.

```sh
# One target; JSON retains structured evidence and notes.
python wordpress_check_windows.py https://test.com --format json --output ../assessment.json

# Authorized text list; keep progress on stderr and results in a file.
python wordpress_check_windows.py --input ../authorized-sites.txt --format csv --output ../assessment.csv --delay 2 --timeout 15

# Shareable offline report, with optional authorized branding.
python wordpress_check_windows.py --input ../authorized-sites.txt --format html --output ../assessment.html --brand "Your Organization" --logo ../logo.png
```

Choose the requested format rather than rerunning every target for each example.
CSV is the default, and omitting `--output` sends results to stdout. JSON retains
arrays; CSV joins arrays with ` | ` and guards spreadsheet-formula strings.
HTML is a self-contained summary report. Use JSON or CSV when full per-target
evidence and timestamps must be preserved; HTML does not expose every field.
`--brand` and `--logo` affect HTML only; a missing logo file is omitted.

`--delay` and `--timeout` must be positive finite numbers. Delay defaults to one
second per origin and can be increased by robots rules. Timeout defaults to 15
seconds **per socket**, not a total run deadline. Add `--contact` only for a
public contact value the user intends to disclose in requests.

Inspect each result even if the process exits with `0`: that means the run
completed, not that every fetch succeeded or every site is patched. Argument or
input-file errors exit with `2`; unexpected I/O errors can raise exceptions.
For blocked or failed targets, report the reason without silently retrying.

On interruption, preserve the output before any rerun. Completed CSV rows are
flushed incrementally; JSON may lack its closing bracket. HTML is rendered from
completed rows during normal finalization, including a handled interruption
path, but a force-killed process may leave it empty. There is no automatic
resume. Determine which targets completed, then run only authorized outstanding
targets into a **new** output file if continuation is requested or already in
scope; do not imply the original run completed.

## Interpret and deliver

| `php2shell_status` | Report this meaning |
| --- | --- |
| `potentially_affected` | An unqualified advertised release is below its branch's upstream fix. Prioritize administrator verification of the actual package and runtime. |
| `fixed_version_reported` | The advertised release meets the embedded branch threshold. This does not verify deployed patch state or certify safety. |
| `unknown` | Evidence cannot support a classification: missing, partial, conflicting, prerelease, vendor-qualified, or outside the covered branches. Preserve the stated reason. |

Read `php2shell_version_status`, `php2shell_notes`, `php2shell_fixed_version`,
and `php2shell_recommendation` alongside the classification. Preserve build
qualifiers: vendors can backport fixes to older base versions. All results have
`php2shell_exploitability=not_tested`; do not infer a PHP SAPI or RCE from a server
header. Do not replace the embedded thresholds with recalled version numbers.
If current patch advice is requested, verify the official sources and clearly
distinguish that advice from the tool's recorded snapshot.

Keep detection `status` and `fetch_status` separate from `php2shell_status`.
`no_evidence` does not prove WordPress is absent; asset `?ver=` hints are not
confirmed WordPress versions. Coarse `fetch_status=blocked` can include HTTP,
TLS, or invalid-input errors; read `status`, `http_status`, and `notes` for the
reason rather than claiming the owner deliberately blocked the check.

Deliver the report path, completed/failed target counts, classification counts,
rule date, and key limitations. Include final URL, observed PHP evidence, and
check timestamp for findings when available. Label any incomplete run. Keep
real target lists and results out of commits; writing a report does not authorize
publishing it, contacting site owners, or changing a server.

## Offline verification

For development or a smoke check, use the repository's local-only suite:

```sh
python -m unittest -v
python wordpress_check_windows.py --help
```

To classify an already supplied version without contacting a website, run from
the checker directory and preserve any vendor suffix:

```sh
python -c "import json; from wordpress_check import assess_php2shell; print(json.dumps(assess_php2shell('8.3.6-0ubuntu0.24.04.13'), indent=2))"
```

Label this as offline version interpretation, not a live observation. For
conflicting supplied values, pass all values through `version_candidates`
instead of selecting one; do not invent a version when none was disclosed.
