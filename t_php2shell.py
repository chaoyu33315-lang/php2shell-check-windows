import csv
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from wordpress_check import (
    Checker, PHP2SHELL_CVES, PHP2SHELL_FIXES, PHP2SHELL_SOURCES,
    Response, Result, assess_php2shell, inspect_page, main,
)


class VersionAssessmentTests(unittest.TestCase):
    def test_each_branch_below_at_and_above_fix(self):
        for (major, minor), fixed in PHP2SHELL_FIXES.items():
            for number, expected in [(fixed - 1, 'potentially_affected'),
                                     (fixed, 'fixed_version_reported'),
                                     (fixed + 1, 'fixed_version_reported')]:
                version = f'{major}.{minor}.{number}'
                with self.subTest(version=version):
                    result = assess_php2shell(version)
                    self.assertEqual(result['php2shell_status'], expected)
                    self.assertEqual(result['php2shell_fixed_version'], f'{major}.{minor}.{fixed}')
                    self.assertEqual(result['php2shell_exploitability'], 'not_tested')
                    self.assertEqual(result['php2shell_cves'], list(PHP2SHELL_CVES))

    def test_old_branch_and_future_branches_need_review(self):
        for version in ['5.6.40', '7.4.33', '8.0.30', '8.1.34', '8.6.0', '9.0.0']:
            with self.subTest(version=version):
                result = assess_php2shell(version)
                self.assertEqual(result['php2shell_status'], 'unknown')
                self.assertEqual(result['php2shell_version_status'], 'branch_requires_vendor_review')

    def test_vendor_backport_cannot_be_judged_by_base_version(self):
        # Ubuntu lists the first package below as a fix despite its older base.
        for version in ['8.3.6-0ubuntu0.24.04.13', '8.2.29-1+deb12u1', '8.3.36-1', '8.5.12+vendor', '8.3.36+arch1']:
            with self.subTest(version=version):
                result = assess_php2shell(version)
                self.assertEqual(result['php2shell_status'], 'unknown')
                self.assertEqual(result['php2shell_version_status'], 'vendor_build_unverified')

    def test_prereleases_never_count_as_fixed_stable_release(self):
        for version in ['8.3.36RC1', '8.3.36-dev', '8.3.99alpha1', '8.5.12~rc2', '8.4.27-beta1']:
            with self.subTest(version=version):
                result = assess_php2shell(version)
                self.assertEqual(result['php2shell_status'], 'unknown')
                self.assertEqual(result['php2shell_version_status'], 'prerelease_unverified')

    def test_partial_or_malformed_versions_are_unknown(self):
        for version in ['8', '8.3', 'latest', '8.3.36 trailing text', '8.3.36/extra', '9' * 5000 + '.0.0']:
            with self.subTest(version=version):
                result = assess_php2shell(version)
                self.assertEqual(result['php2shell_status'], 'unknown')
                self.assertEqual(result['php2shell_version_status'], 'unrecognized_or_partial_version')

    def test_missing_version_does_not_mean_safe(self):
        for hint in [True, False]:
            result = assess_php2shell('', php_hint=hint)
            self.assertEqual(result['php2shell_status'], 'unknown')
            self.assertEqual(result['php2shell_version_status'], 'version_not_disclosed')

    def test_conflicting_versions_are_not_reduced_to_one(self):
        result = assess_php2shell(version_candidates=['8.3.35', '8.3.36'])
        self.assertEqual(result['php2shell_status'], 'unknown')
        self.assertEqual(result['php2shell_version_status'], 'conflicting_versions')
        self.assertEqual(assess_php2shell(version_candidates=['8.3.35', '8.3.35'])['php2shell_status'], 'potentially_affected')

    def test_rules_include_provenance_and_no_confirmation_claim(self):
        result = assess_php2shell('8.4.26')
        self.assertEqual(result['php2shell_rules_as_of'], '2026-10-21')
        self.assertEqual(result['php2shell_sources'], list(PHP2SHELL_SOURCES))
        self.assertNotIn('confirmed', result['php2shell_status'])
        self.assertIn('backports', ' '.join(result['php2shell_notes']))


class HeaderAndWorkflowTests(unittest.TestCase):
    def inspect(self, headers, body='<title>Test</title>', status=200):
        result = Result('https://example.test/', final_url='https://example.test/')
        inspect_page(Response(status, headers, body, False), result)
        return result

    def test_non_wordpress_php_site_is_assessed(self):
        result = self.inspect({'x-powered-by': 'PHP/8.3.35'})
        self.assertEqual(result.status, 'no_evidence')
        self.assertEqual(result.php2shell_status, 'potentially_affected')

    def test_php_in_server_header_is_recorded(self):
        result = self.inspect({'server': 'Apache PHP/8.5.12'})
        self.assertEqual(result.php_version, '8.5.12')
        self.assertEqual(result.php2shell_status, 'fixed_version_reported')
        self.assertTrue(result.php_evidence[0].startswith('Server:'))

    def test_conflicting_headers_and_repeated_identical_versions(self):
        result = self.inspect({'server': 'Apache PHP/8.3.35', 'x-powered-by': 'PHP/8.3.36'})
        self.assertEqual(result.php_version, '')
        self.assertEqual(result.php_version_candidates, ['8.3.35', '8.3.36'])
        self.assertEqual(result.php2shell_version_status, 'conflicting_versions')
        same = self.inspect({'server': 'Apache PHP/8.3.36', 'x-powered-by': 'PHP/8.3.36'})
        self.assertEqual(same.php2shell_status, 'fixed_version_reported')

    def test_proxy_server_and_wordpress_version_do_not_prove_php_patch(self):
        result = self.inspect({'server': 'cloudflare'}, '<meta name="generator" content="WordPress 8.5.12">')
        self.assertEqual(result.status, 'wordpress')
        self.assertEqual(result.php2shell_status, 'unknown')
        self.assertEqual(result.php_version, '')

    def test_vendor_package_header_preserves_qualifier(self):
        result = self.inspect({'x-powered-by': 'PHP/8.3.6-0ubuntu0.24.04.13'})
        self.assertEqual(result.php_version, '8.3.6-0ubuntu0.24.04.13')
        self.assertEqual(result.php2shell_version_status, 'vendor_build_unverified')

    def test_unparseable_header_is_not_truncated_to_fixed_version(self):
        result = self.inspect({'x-powered-by': 'PHP/8.3.36/garbage'})
        self.assertEqual(result.php_version, '')
        self.assertEqual(result.php2shell_status, 'unknown')

    def test_unknown_version_and_denied_response(self):
        result = self.inspect({'x-powered-by': 'PHP'})
        self.assertEqual(result.php2shell_status, 'unknown')
        blocked = self.inspect({'x-powered-by': 'PHP/8.3.35'}, status=403)
        self.assertEqual(blocked.status, 'blocked')
        self.assertEqual(blocked.php2shell_exploitability, 'not_tested')

    def test_assessment_does_not_add_any_network_requests(self):
        replies = [Response(200, {}, 'User-agent: *\nAllow: /', False),
                   Response(200, {'x-powered-by': 'PHP/8.4.26'}, '<p>test</p>', False)]
        with patch.object(Checker, 'request', side_effect=replies) as request:
            result = Checker().check('https://example.test/')
        self.assertEqual(result.php2shell_status, 'potentially_affected')
        self.assertEqual([call.args[0] for call in request.call_args_list],
                         ['https://example.test/robots.txt', 'https://example.test/'])

    def test_robots_denial_gets_unknown_assessment_without_page_fetch(self):
        with patch.object(Checker, 'request', return_value=Response(200, {}, 'User-agent: *\nDisallow: /', False)) as request:
            result = Checker().check('https://example.test/')
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result.status, 'blocked')
        self.assertEqual(result.php2shell_status, 'unknown')

    def test_network_failure_still_has_assessment_metadata(self):
        with patch.object(Checker, 'request', side_effect=TimeoutError('fixture timeout')):
            result = Checker().check('https://example.test/')
        self.assertEqual(result.fetch_status, 'timeout')
        self.assertEqual(result.php2shell_status, 'unknown')
        self.assertEqual(result.php2shell_exploitability, 'not_tested')

    def test_cli_json_and_csv_include_php2shell_fields(self):
        for fmt in ['json', 'csv']:
            replies = [Response(200, {}, 'User-agent: *\nAllow: /', False),
                       Response(200, {'x-powered-by': 'PHP/8.2.34'}, '<p>test</p>', False)]
            output = io.StringIO()
            with patch.object(Checker, 'request', side_effect=replies), redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['https://example.test/', '--format', fmt]), 0)
            rows = json.loads(output.getvalue()) if fmt == 'json' else list(csv.DictReader(io.StringIO(output.getvalue())))
            self.assertEqual(rows[0]['php2shell_status'], 'potentially_affected')
            self.assertEqual(rows[0]['php2shell_exploitability'], 'not_tested')

    def test_cli_html_report_is_branded_escaped_and_script_free(self):
        replies = [Response(200, {}, 'User-agent: *\nAllow: /', False),
                   Response(200, {'x-powered-by': 'PHP/8.2.34'}, '<p>test</p>', False)]
        output = io.StringIO()
        with patch.object(Checker, 'request', side_effect=replies), redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(main(['https://example.test/?q=<b>', '--format', 'html', '--brand', 'Acme & Co']), 0)
        report = output.getvalue()
        self.assertIn('Potentially affected', report)
        self.assertIn('8.2.35', report)
        self.assertIn('Acme &amp; Co', report)
        self.assertIn('data:image/png;base64,', report)
        self.assertNotIn('?q=<b>', report)
        self.assertNotIn('<script', report)


if __name__ == '__main__':
    unittest.main()
