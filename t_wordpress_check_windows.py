import csv
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from wordpress_check import Checker, Response, Result, RobotsPolicy, csv_safe, inspect_page, main, normalize_url


class RobotsTests(unittest.TestCase):
    def test_wildcards_anchors_and_longest_allow(self):
        rules = RobotsPolicy("User-agent: *\nDisallow: /*private\nAllow: /private/public\nDisallow: /*.php$", 1)
        self.assertFalse(rules.can_fetch("https://test/a/private"))
        self.assertTrue(rules.can_fetch("https://test/private/public"))
        self.assertFalse(rules.can_fetch("https://test/index.php"))
        self.assertTrue(rules.can_fetch("https://test/index.php?ok=1"))

    def test_agent_selection_and_merged_groups(self):
        rules = RobotsPolicy("User-agent: *\nDisallow: /\nUser-agent: WordPressPublicChecker\nDisallow: /one\nUser-agent: WordPressPublicChecker\nDisallow: /two", 1)
        self.assertTrue(rules.can_fetch("https://test/"))
        self.assertFalse(rules.can_fetch("https://test/one"))
        self.assertFalse(rules.can_fetch("https://test/two"))

    def test_percent_encoding(self):
        rules = RobotsPolicy("User-agent: *\nDisallow: /private\nDisallow: /a%2Fb\nDisallow: /café", 1)
        self.assertFalse(rules.can_fetch("https://test/%70rivate"))
        self.assertFalse(rules.can_fetch("https://test/a%2fb"))
        self.assertTrue(rules.can_fetch("https://test/a/b"))
        self.assertFalse(rules.can_fetch("https://test/caf%C3%A9"))

    def test_decimal_delay_and_rate(self):
        rules = RobotsPolicy("User-agent: *\nCrawl-delay: 1.5\nRequest-rate: 2/8", 1)
        self.assertEqual(rules.delay, 4)


class DetectionTests(unittest.TestCase):
    def inspect(self, body, headers=None, status=200, truncated=False):
        result = Result("https://example.test", final_url="https://example.test/")
        inspect_page(Response(status, headers or {}, body, truncated), result)
        return result

    def test_generator_and_php(self):
        r = self.inspect('<title>A &amp; B</title><meta content="WordPress 6.8.3" name="generator">', {"x-powered-by": "PHP/8.3.12"})
        self.assertEqual((r.status, r.wordpress_version, r.php_version, r.title), ("wordpress", "6.8.3", "8.3.12", "A & B"))

    def test_asset_version_is_only_a_hint(self):
        r = self.inspect('<script src="/wp-content/plugins/plugin/main.js?ver=9.9"></script>')
        self.assertEqual(r.status, "likely_wordpress")
        self.assertEqual(r.wordpress_version, "")
        self.assertTrue(r.asset_version_hints)

    def test_rest_discovery(self):
        for body, headers in [('<link rel="https://api.w.org/" href="/wp-json/">', {}), ("", {"link": '</wp-json/>; rel="https://api.w.org/"'})]:
            self.assertEqual(self.inspect(body, headers).status, "wordpress")

    def test_prose_and_links_are_not_wordpress_evidence(self):
        r = self.inspect('<p>WordPress /wp-content/</p><a href="https://someone.test/wp-content/test">Article</a>')
        self.assertEqual(r.status, "no_evidence")

    def test_conflicting_generator_versions(self):
        r = self.inspect('<meta name="generator" content="WordPress 6.7"><meta name="generator" content="WordPress 6.8">')
        self.assertEqual(r.wordpress_version, "")
        self.assertIn("Conflicting", " ".join(r.notes))

    def test_block_and_truncation(self):
        self.assertEqual(self.inspect('WordPress', status=403).status, "blocked")
        self.assertEqual(self.inspect('<p>hello</p>', truncated=True).status, "uncertain")

    def test_input_and_csv_safety(self):
        self.assertEqual(normalize_url("example.test"), "https://example.test/")
        for value in ("file:///etc/passwd", "https://user:secret@example.test", "https://a.test/\r\nbad", "https://example.test:bad"):
            with self.assertRaises(ValueError):
                normalize_url(value)
        self.assertEqual(csv_safe("  =HYPERLINK(1)"), "'  =HYPERLINK(1)")


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.routes = {}
        cls.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.requests.append(self.path)
                status, headers, body = cls.routes.get(self.path, (404, {}, ""))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.routes.clear()
        self.requests.clear()
        self.routes["/robots.txt"] = (200, {"Content-Type": "text/plain"}, "User-agent: *\nDisallow: /private\n")
        self.routes["/"] = (200, {"Content-Type": "text/html", "X-Powered-By": "PHP/8.3.1"}, '<meta name="generator" content="WordPress 6.8">')

    def checker(self):
        return Checker(delay=0, timeout=2)

    def test_allowed_page(self):
        r = self.checker().check(self.base)
        self.assertEqual(r.status, "wordpress")
        self.assertEqual(self.requests, ["/robots.txt", "/"])

    def test_denied_url_is_never_requested(self):
        self.assertEqual(self.checker().check(self.base + "/private").status, "blocked")
        self.assertEqual(self.requests, ["/robots.txt"])

    def test_redirect_target_is_checked(self):
        self.routes["/"] = (302, {"Location": "/private"}, "")
        self.assertEqual(self.checker().check(self.base).status, "blocked")
        self.assertEqual(self.requests, ["/robots.txt", "/"])

    def test_robots_fail_closed(self):
        for status, body in [(403, ""), (429, ""), (500, ""), (200, "<!doctype html><html>challenge</html>")]:
            self.requests.clear()
            self.routes["/robots.txt"] = (status, {}, body)
            self.assertEqual(self.checker().check(self.base).status, "blocked")
            self.assertEqual(self.requests, ["/robots.txt"])

    def test_missing_robots_and_no_evidence(self):
        self.routes["/robots.txt"] = (404, {}, "")
        self.routes["/"] = (200, {}, "<p>hello</p>")
        self.assertEqual(self.checker().check(self.base).status, "no_evidence")

    def test_same_origin_robots_redirect(self):
        self.routes["/robots.txt"] = (302, {"Location": "/robots-policy"}, "")
        self.routes["/robots-policy"] = (200, {}, "User-agent: *\nDisallow: /private")
        self.assertEqual(self.checker().check(self.base + "/private").status, "blocked")
        self.assertEqual(self.requests, ["/robots.txt", "/robots-policy"])

    def test_cross_origin_robots_redirect_stops(self):
        self.routes["/robots.txt"] = (302, {"Location": "https://example.invalid/robots.txt"}, "")
        self.assertEqual(self.checker().check(self.base).status, "blocked")
        self.assertEqual(self.requests, ["/robots.txt"])

    def test_crawl_delay(self):
        self.routes["/robots.txt"] = (200, {}, "User-agent: *\nCrawl-delay: 2\n")
        with patch("wordpress_check.time.sleep") as sleep:
            self.assertEqual(self.checker().check(self.base).status, "wordpress")
        self.assertGreater(sleep.call_args.args[0], 1)

    def test_canonical_www_robots_redirect_is_allowed(self):
        checker = self.checker()
        checker.request = Mock(side_effect=[
            Response(301, {'location': 'https://www.example.test/robots.txt'}, '', False),
            Response(200, {}, 'User-agent: *\nDisallow: /private', False),
        ])
        self.assertEqual(checker.policy('https://example.test/'), 0)
        with self.assertRaisesRegex(Exception, 'disallows'):
            checker.policy('https://example.test/private')

    def test_canonical_robots_downgrade_is_blocked(self):
        checker = self.checker()
        checker.request = Mock(return_value=Response(301, {'location': 'http://www.example.test/robots.txt'}, '', False))
        with self.assertRaisesRegex(Exception, 'another origin'):
            checker.policy('https://example.test/')

    def test_long_crawl_delay_defers_without_requesting_page(self):
        checker = self.checker()
        checker.request = Mock(return_value=Response(200, {}, 'User-agent: *\nCrawl-delay: 3600', False))
        result = checker.check('https://example.test/')
        self.assertEqual(result.status, 'blocked')
        self.assertIn('3600-second', result.notes[-1])
        self.assertEqual(checker.request.call_count, 1)

    def test_cli_csv_json_and_deduplication(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sites.txt"
            source.write_text(f"# example\n{self.base}\n{self.base}\n", encoding="utf-8")
            for fmt in ("csv", "json"):
                output = Path(temp) / f"results.{fmt}"
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["--input", str(source), "--format", fmt, "--output", str(output), "--delay", "0.001"]), 0)
                content = output.read_text(encoding="utf-8")
                rows = json.loads(content) if fmt == "json" else list(csv.DictReader(io.StringIO(content)))
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["status"], "wordpress")


if __name__ == "__main__":
    unittest.main()
