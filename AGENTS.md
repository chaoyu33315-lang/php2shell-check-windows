# Repository instructions

Read [README.md](README.md) for setup and usage,
[CONTRIBUTING.md](CONTRIBUTING.md) before changing the project, and
[SECURITY.md](SECURITY.md) for security-reporting boundaries.

## Project map

- `wordpress_check.py`: single-file, standard-library-only Python 3.10+ CLI,
  passive fetcher, PHP2Shell classifier, and CSV/JSON/HTML report rendering.
- `test_wordpress_check.py` and `test_php2shell.py`: local HTTP fixtures and mocks.
- `docs/REFERENCE.md`: command options, output fields, and request behavior.
- `docs/PHP2SHELL.md`: source-linked classification rules and limitations.
- `skills/php2shell-check/SKILL.md`: reusable instructions for agents using the
  checker; `agents/openai.yaml` inside that skill provides discovery metadata.
- `CLAUDE.md`: points Claude to these shared instructions; keep policy here.
- `integrations/worker/`: restricted network adapter and authenticated queue
  controller; the public CLI remains independent of this integration.
- `integrations/wordpress/`: WordPress MU plugin and database integration tests.
- `deployment/`: isolated worker container, disposable WordPress fixture, and
  reviewed CompleteTech site patch. Read `docs/WORDPRESS.md` before deployment.

## Implementation constraints

Keep the checker usable as one Python file with no third-party runtime or test
dependencies. Preserve public-page-only requests, verified TLS, robots checks,
the descriptive User-Agent, pacing, response-size limits, and bounded redirects.
Do not add exploit probes, authentication bypasses, or automatic retries around
access restrictions. Running tests or editing this repository does not authorize
scanning real websites.

Advertised versions are evidence, not verified runtime state. Keep missing,
conflicting, prerelease, vendor-qualified, and uncovered-branch cases uncertain.
Never turn `fixed_version_reported` into a guarantee of safety or
`potentially_affected` into confirmed exploitability. Preserve
`php2shell_exploitability=not_tested` and the distinction between fetch,
WordPress-detection, and PHP2Shell results.

Change the embedded fix table or rule date only after checking the official
advisories. Add branch-boundary and vendor-qualification tests with such changes.
Keep CLI/output changes aligned with the reference, README, and agent skill.
For the skill, use the real CLI rather than a second scanner implementation;
keep it usable after installation outside this checkout.

## Validation and delivery

Run from the repository root:

```sh
python -m unittest -v
python wordpress_check.py --help
git diff --check
```

The suite uses mocks and ephemeral local HTTP servers; it must not contact
external websites. Add focused tests for behavior changes. For documentation
or skill edits, check commands against `--help` and source, verify referenced
paths, and validate skill frontmatter/UI metadata with the skill tooling when
available. Do not add tests that only assert prose wording.

Use focused branches and pull requests linked to their issues. Preserve unrelated
work. Keep real target lists, reports, workbooks, credentials, and private contact
data out of commits. Verify CI for the actual PR head, resolve review findings,
and merge only when authorized. Report local checks, hosted CI, and any live
observations separately. Follow [LICENSING.md](LICENSING.md) and
[BRAND_ASSETS.md](BRAND_ASSETS.md) when distributing code or branded reports.
