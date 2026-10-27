"""Offline regression tests for the authenticated scanner worker."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from urllib.request import Request

from wordpress_check import Result, annotate_php2shell

from integrations.worker import network
from integrations.worker.network import PinnedOpener, RequestOrigin
from integrations.worker.protocol import (
    APIClient,
    APIError,
    JobClaim,
    auth_headers,
    validate_claim,
)
from integrations.worker.runner import ScannerFailure, SubprocessRunner
from integrations.worker.service import (
    CALLBACK_LEASE_GRACE_SECONDS,
    WorkerService,
)
from integrations.worker.spool import DurableSpool


REVISION = "a" * 40
NOW = 1_800_000_000
TARGET = "https://example.test/"
LEASE = "lease-token-0123456789"
SCOPE_HASH = hashlib.sha256(TARGET.encode("utf-8")).hexdigest()
TERMS_HASH = "b" * 64


def _claim(*, expires_at=NOW + 7200, lease_until=NOW + 600, target=TARGET):
    return JobClaim(
        23,
        target,
        hashlib.sha256(target.encode("utf-8")).hexdigest(),
        TERMS_HASH,
        datetime.fromtimestamp(expires_at, timezone.utc),
        LEASE,
        datetime.fromtimestamp(lease_until, timezone.utc),
    )


def _result(target=TARGET):
    result = Result(
        input_url=target,
        final_url=target,
        status="no_evidence",
        fetch_status="ok",
        http_status=200,
    )
    annotate_php2shell(result)
    return asdict(result)


class _Response:
    def __init__(self, body=b'{"ok":true}', code=200):
        self.body = body
        self.code = code

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _FakeAPI:
    def __init__(self, claim=None, *, start_error=None, result_errors=(), result_response=None):
        self.claim_value = claim
        self.start_error = start_error
        self.result_errors = list(result_errors)
        self.result_response = result_response or {"ok": True}
        self.claim_calls = 0
        self.start_calls = []
        self.result_bodies = []

    def claim(self):
        self.claim_calls += 1
        return self.claim_value

    def start(self, claim):
        self.start_calls.append(claim)
        if self.start_error:
            raise self.start_error
        return True

    def control_claim(self):
        return None

    def result(self, body):
        self.result_bodies.append(body)
        if self.result_errors:
            error = self.result_errors.pop(0)
            if error:
                raise error
        return self.result_response


class _UnusedGate:
    """The isolation fixtures never contact a target, so their gate is never consulted."""

    def admit(self):
        raise AssertionError("fixture scanner unexpectedly asked for admission")

    def probe(self):
        return None


class _FakeRunner:
    def __init__(self, result=None):
        self.result = result or _result()
        self.calls = []

    def run(self, target, *, timeout, stop_event=None, gate=None):
        self.calls.append((target, timeout, stop_event, gate))
        result = dict(self.result)
        result["input_url"] = target
        result["final_url"] = target
        return result


class WorkerProtocolTests(unittest.TestCase):
    def test_hmac_canonicalization_uses_exact_raw_body_and_route(self):
        secret = b"s" * 32
        body = b'{"id":23,"lease":"opaque"}'
        headers = auth_headers(secret, 1234, "0" * 32, "/ct-scan/v1/result", body)
        canonical = b"1234\n" + b"0" * 32 + b"\nPOST\n/ct-scan/v1/result\n" + hashlib.sha256(body).hexdigest().encode()
        expected = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-CT-Signature"], expected)
        self.assertEqual(headers["X-CT-Timestamp"], "1234")
        self.assertEqual(headers["X-CT-Nonce"], "0" * 32)
        with self.assertRaises(ValueError):
            auth_headers(secret, 1234, "0" * 32, "/wrong", body)

    def test_api_client_sends_signed_json_body_to_fixed_route(self):
        captured = []

        class Transport:
            def open(self, request, timeout=None):
                captured.append((request, timeout))
                return _Response()

        client = APIClient(
            b"k" * 32,
            transport=Transport(),
            clock=lambda: 1700000000,
            nonce_factory=lambda: "1" * 32,
        )
        self.assertEqual(client.post("/ct-scan/v1/start", {"id": 1}), {"ok": True})
        request, timeout = captured[0]
        self.assertEqual(request.full_url, "https://complete.tech/wp-json/ct-scan/v1/start")
        self.assertEqual(request.data, b'{"id":1}')
        self.assertEqual(timeout, 10.0)
        expected = auth_headers(b"k" * 32, 1700000000, "1" * 32, "/ct-scan/v1/start", request.data)
        actual_headers = {name.lower(): value for name, value in request.header_items()}
        for name, value in expected.items():
            self.assertEqual(actual_headers[name.lower()], value)

    def test_claim_requires_canonical_target_binding_and_unix_integer_times(self):
        now = datetime.fromtimestamp(NOW, timezone.utc)
        value = {
            "job": {
                "id": 23,
                "target": TARGET,
                "scope_hash": SCOPE_HASH,
                "terms_hash": TERMS_HASH,
                "expires_at": NOW + 3600,
                "lease": LEASE,
                "lease_until": NOW + 300,
            }
        }
        parsed = validate_claim(value, now=now)
        self.assertEqual(parsed.target, TARGET)
        self.assertEqual(int(parsed.lease_until.timestamp()), NOW + 300)
        for invalid_time in (True, str(NOW + 300), NOW + 0.5):
            broken = json.loads(json.dumps(value))
            broken["job"]["lease_until"] = invalid_time
            with self.subTest(invalid_time=invalid_time), self.assertRaises(APIError):
                validate_claim(broken, now=now)
        for target in (
            "https://example.test/path/",
            "https://example.test/?q=x",
            "https://user@example.test/",
            "https://127.0.0.1/",
            "https://example.test:8443/",
        ):
            broken = json.loads(json.dumps(value))
            broken["job"]["target"] = target
            broken["job"]["scope_hash"] = hashlib.sha256(target.encode()).hexdigest()
            with self.subTest(target=target), self.assertRaises(APIError):
                validate_claim(broken, now=now)


class WorkerNetworkTests(unittest.TestCase):
    def test_origin_scope_normalizes_and_rejects_unapproved_targets(self):
        scope, normalized = RequestOrigin.from_target("HTTP://ExAmPle.test:80/")
        self.assertEqual(normalized, "http://example.test/")
        self.assertEqual(scope.validate_request("http://example.test/robots.txt")[0:3], ("http", 80, "example.test"))
        self.assertEqual(scope.validate_request("https://example.test/", mark_upgrade=True)[0:2], ("https", 443))
        with self.assertRaises(ValueError):
            scope.validate_request("http://example.test/page")
        with self.assertRaises(ValueError):
            RequestOrigin.from_target("https://example.test/after-upgrade")
        for target in (
            "https://example.test/a",
            "https://example.test/?q=1",
            "https://example.test/#frag",
            "https://u:p@example.test/",
            "https://example.test:444/",
            "https://127.0.0.1/",
            "https://bad..example/",
            "https://example.test/\n",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                RequestOrigin.from_target(target)

    def test_original_http_target_may_report_only_same_host_https_upgrade(self):
        target = "http://example.test/"
        scope, _ = RequestOrigin.from_target(target)
        upgraded = _result(target)
        upgraded["final_url"] = "https://example.test/"
        self.assertIs(SubprocessRunner.validate_result(upgraded, target, scope), upgraded)
        outside = dict(upgraded, final_url="https://attacker.example.test/")
        with self.assertRaises(ScannerFailure):
            SubprocessRunner.validate_result(outside, target, scope)

    @staticmethod
    def _answer(text):
        address = __import__("ipaddress").ip_address(text)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sockaddr = (text, 443, 0, 0) if family == socket.AF_INET6 else (text, 443)
        return (family, socket.SOCK_STREAM, 6, "", sockaddr)

    def test_public_dns_validation_rejects_mixed_and_special_addresses(self):
        self.assertEqual(
            network._public_addresses("example.test", 443, resolver=lambda *_a, **_k: [self._answer("8.8.8.8")]),
            [(socket.AF_INET, "8.8.8.8")],
        )
        self.assertEqual(
            network._public_addresses(
                "example.test", 443, resolver=lambda *_a, **_k: [self._answer("2606:4700:4700::1111")]
            ),
            [(socket.AF_INET6, "2606:4700:4700::1111")],
        )
        rejected = (
            "10.0.0.1",
            "224.0.0.1",
            "192.0.0.9",
            "192.88.99.1",
            "::1",
            "ff02::1",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2001::1",
            "fec0::1",
        )
        for address in rejected:
            with self.subTest(address=address), self.assertRaises(ValueError):
                network._public_addresses("example.test", 443, resolver=lambda *_a, **_k: [self._answer(address)])
        with self.assertRaises(ValueError):
            network._public_addresses(
                "example.test",
                443,
                resolver=lambda *_a, **_k: [self._answer("8.8.8.8"), self._answer("10.0.0.1")],
            )

    def test_pinned_opener_resolves_every_request_and_rejects_rebinding(self):
        scope, _ = RequestOrigin.from_target(TARGET)
        answers = iter(([self._answer("8.8.8.8")], [self._answer("10.0.0.1")]))
        resolver = mock.Mock(side_effect=lambda *_a, **_k: next(answers))
        opened = []

        class Connection:
            def __init__(self, host, port, **kwargs):
                opened.append(kwargs["pinned_address"])

            def request(self, *_args, **_kwargs):
                return None

            def getresponse(self):
                return type("R", (), {"status": 200, "headers": {}, "read": lambda _s, n=-1: b"ok", "close": lambda _s: None})()

            def close(self):
                return None

        with mock.patch.object(network, "PinnedHTTPSConnection", Connection):
            opener = PinnedOpener(scope, resolver=resolver)
            with opener.open(Request(TARGET)) as response:
                self.assertEqual(response.read(), b"ok")
            with self.assertRaises(ValueError):
                opener.open(Request(TARGET))
        self.assertEqual(resolver.call_count, 2)
        self.assertEqual(opened, ["8.8.8.8"])

    def test_cross_host_is_rejected_before_dns_and_tls_keeps_original_sni(self):
        scope, _ = RequestOrigin.from_target(TARGET)
        resolver = mock.Mock()
        opener = PinnedOpener(scope, resolver=resolver)
        with self.assertRaises(ValueError):
            opener.open(Request("https://attacker.example.test/"))
        resolver.assert_not_called()

        calls = []

        class RawSocket:
            def close(self):
                return None

        class TLSContext:
            verify_mode = network.ssl.CERT_REQUIRED
            check_hostname = True

            def wrap_socket(self, raw, *, server_hostname):
                calls.append(server_hostname)
                return raw

        connection = network.PinnedHTTPSConnection(
            "example.test", 443, pinned_family=socket.AF_INET, pinned_address="8.8.8.8", context=TLSContext()
        )
        with mock.patch.object(network, "_connect_socket", return_value=RawSocket()):
            connection.connect()
        self.assertEqual(calls, ["example.test"])
        connection.close()

    def test_pinned_opener_transmits_request_body_to_local_fixture(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append((self.path, body))
                payload = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)

        class LocalScope:
            def validate_request(self, url):
                from urllib.parse import urlsplit, urlunsplit

                parts = urlsplit(url)
                if parts.scheme != "http" or parts.hostname != "example.test":
                    raise ValueError("request_out_of_scope")
                return "http", server.server_port, "example.test", urlunsplit(("", "", parts.path or "/", parts.query, ""))

        with mock.patch.object(network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]):
            opener = PinnedOpener(LocalScope())
            request = Request("http://example.test/receipt", data=b'{"signed":true}', method="POST")
            with opener.open(request, timeout=2) as response:
                self.assertEqual(response.read(), b"ok")
        self.assertEqual(received, [("/receipt", b'{"signed":true}')])

    def test_page_and_robots_redirects_cannot_escape_scope(self):
        for mode, expected_status in (("page", "error"), ("robots", "blocked"), ("robots_www", "error")):
            requested = []
            resolver_hosts = []

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    requested.append(self.path)
                    if self.path == "/robots.txt" and mode in {"robots", "robots_www"}:
                        self.send_response(302)
                        location = (
                            "http://attacker.example.test/robots.txt"
                            if mode == "robots"
                            else "http://www.example.test/robots.txt"
                        )
                        self.send_header("Location", location)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if self.path == "/robots.txt":
                        body = b"User-agent: *\nAllow: /\n"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                    elif self.path == "/" and mode == "page":
                        body = b""
                        self.send_response(302)
                        self.send_header("Location", "http://attacker.example.test/")
                    else:
                        body = b"<html><title>fixture</title></html>"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *_args):
                    return

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            class FixtureScope:
                def validate_request(self, url):
                    from urllib.parse import urlsplit, urlunsplit

                    parts = urlsplit(url)
                    if parts.scheme != "http" or parts.hostname != "example.test":
                        raise ValueError("request_out_of_scope")
                    return "http", server.server_port, "example.test", urlunsplit(("", "", parts.path or "/", parts.query, ""))

            def fixture_addresses(host, port, resolver):
                resolver_hosts.append(host)
                if host != "example.test":
                    raise AssertionError("unapproved host reached DNS")
                return [(socket.AF_INET, "127.0.0.1")]

            try:
                checker = __import__("wordpress_check").Checker(timeout=2, delay=0)
                checker.opener = PinnedOpener(FixtureScope())
                with mock.patch.object(network, "_public_addresses", side_effect=fixture_addresses):
                    result = checker.check("http://example.test/")
                self.assertEqual(result.status, expected_status)
                self.assertTrue(resolver_hosts)
                self.assertTrue(all(host == "example.test" for host in resolver_hosts))
                if mode == "page":
                    self.assertEqual(requested, ["/robots.txt", "/"])
                else:
                    self.assertEqual(requested, ["/robots.txt"])
            finally:
                server.shutdown()
                thread.join(2)
                server.server_close()


class WorkerSpoolServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spool = DurableSpool(Path(self.temp.name) / "spool")
        self.spool.prepare()
        self.clock_value = NOW
        self.api = _FakeAPI()
        self.runner = _FakeRunner()
        self.service = WorkerService(
            self.api,
            self.spool,
            self.runner,
            REVISION,
            clock=lambda: self.clock_value,
        )

    def _save_receipt(self, claim=None):
        claim = claim or _claim()
        body = self.service._callback_body(claim.job_id, claim.lease, claim.scope_hash, "failed", None, "scanner_failed")
        return claim, body, self.spool.save_callback(claim, body)

    def test_start_ack_loss_never_restarts_or_scans_same_lease(self):
        self.api.claim_value = _claim()
        self.api.start_error = APIError("api_network_error")
        self.assertEqual(self.service.process_once(), "start_uncertain")
        self.assertEqual(self.service.process_once(), "waiting_for_lease")
        self.assertEqual(self.api.claim_calls, 1)
        self.assertEqual(len(self.api.start_calls), 1)
        self.assertEqual(self.runner.calls, [])

    def test_scan_saves_receipt_then_posts_successfully(self):
        claim = _claim()
        self.api.claim_value = claim
        self.assertEqual(self.service.process_once(), "callback_accepted")
        self.assertEqual(len(self.api.start_calls), 1)
        self.assertEqual(len(self.runner.calls), 1)
        self.assertEqual(len(self.api.result_bodies), 1)
        receipt = json.loads(self.api.result_bodies[0])
        self.assertEqual(receipt["outcome"], "completed")
        self.assertEqual(receipt["error"], "")
        self.assertEqual(receipt["checker_revision"], REVISION)
        self.assertEqual(self.spool.callback_records(), [])

    def test_result_retry_reuses_durable_body_without_rescan(self):
        claim, body, _path = self._save_receipt()
        self.api.result_errors = [APIError("api_network_error"), None]
        self.assertEqual(self.service.process_once(), "callback_pending_api_network_error")
        self.assertEqual(self.service.process_once(), "callback_accepted")
        self.assertEqual(self.api.result_bodies, [body, body])
        self.assertEqual(self.api.claim_calls, 0)
        self.assertEqual(self.api.start_calls, [])
        self.assertEqual(self.runner.calls, [])

    def test_restart_recovery_of_running_marker_posts_failure_without_rescan(self):
        claim = _claim()
        self.spool.save_running(claim, REVISION, NOW - 181)
        self.assertEqual(self.service.process_once(), "callback_accepted")
        self.assertEqual(self.runner.calls, [])
        receipt = json.loads(self.api.result_bodies[0])
        self.assertEqual(receipt["outcome"], "failed")
        self.assertEqual(receipt["error"], "scanner_interrupted")
        self.assertEqual(self.spool.callback_records(), [])

    def test_permanent_callback_rejections_quarantine_payload(self):
        for status in (400, 409, 410, 413, 422):
            with self.subTest(status=status):
                claim, body, _path = self._save_receipt(_claim())
                self.api.result_errors = [APIError(f"api_http_{status}", status=status)]
                self.assertEqual(self.service.process_once(), "callback_quarantined")
                files = list(self.spool.quarantine.glob("receipt-*.json"))
                matching = [json.loads(item.read_text("utf-8")) for item in files]
                record = next(item for item in matching if item["id"] == claim.job_id)
                self.assertEqual(base64.b64decode(record["payload_b64"]), body)
                self.assertEqual(record["reason"], f"api_http_{status}")
                self.assertEqual(self.spool.callback_records(), [])

    def test_callback_retry_window_is_bounded_by_lease_grace_and_authorization(self):
        claim = _claim(expires_at=NOW + 9000, lease_until=NOW + 600)
        _claim_value, body, _path = self._save_receipt(claim)
        self.clock_value = NOW + 600 + CALLBACK_LEASE_GRACE_SECONDS
        self.assertEqual(self.service.process_once(), "callback_quarantined")
        self.assertEqual(self.api.result_bodies, [])
        record = json.loads(next(self.spool.quarantine.glob("receipt-*.json")).read_text("utf-8"))
        self.assertEqual(record["reason"], "callback_retry_window_expired")
        self.assertEqual(base64.b64decode(record["payload_b64"]), body)

    def test_idle_poll_updates_heartbeat_and_prunes_expired_quarantine(self):
        self.spool._quarantine(99, "c" * 24, "old_receipt", b"private", NOW)
        self.clock_value = NOW + 365 * 24 * 60 * 60 + 1
        self.api.claim_value = None
        self.assertEqual(self.service.process_once(), "idle")
        self.assertEqual(list(self.spool.quarantine.iterdir()), [])
        self.assertEqual(json.loads(self.spool.heartbeat_path.read_text("utf-8")), {"last_poll_epoch": self.clock_value})

    def test_generated_atomic_write_temporary_file_is_recovered(self):
        temp = self.spool.pending / f".tmp-{os.getpid()}-0123456789abcdef"
        temp.write_bytes(b"interrupted")
        temp.chmod(0o600)
        self.spool.cleanup_temps()
        self.assertFalse(temp.exists())

    def test_contradictory_and_extended_scanner_results_are_rejected(self):
        scope, _ = RequestOrigin.from_target(TARGET)
        contradictory = _result()
        contradictory.update(status="error", fetch_status="dns_error", http_status=None)
        contradictory["php2shell_status"] = "fixed_version_reported"
        with self.assertRaises(ScannerFailure):
            SubprocessRunner.validate_result(contradictory, TARGET, scope)
        extended = dict(_result(), unrecognized="extra")
        with self.assertRaises(ScannerFailure):
            SubprocessRunner.validate_result(extended, TARGET, scope)


@unittest.skipUnless(
    os.name == "posix" and __import__("sys").platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0,
    "real child UID isolation requires Linux root",
)
class WorkerSubprocessIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        root.chmod(0o755)
        integrations = root / "integrations"
        worker = integrations / "worker"
        worker.mkdir(parents=True)
        integrations.chmod(0o755)
        worker.chmod(0o755)
        (integrations / "__init__.py").write_text("", encoding="utf-8")
        (worker / "__init__.py").write_text("", encoding="utf-8")
        self.secret = root / "parent-only-key"
        self.secret.write_bytes(b"supervisor-secret-material")
        self.secret.chmod(0o600)
        result_literal = repr(json.dumps(_result(), separators=(",", ":")))
        script = f'''import json, os, socket, sys, time
from urllib.parse import urlsplit
def safe_excepthook(kind, _value, _traceback):
    sys.stdout.write(json.dumps({{"ok":False,"error":"fixture_" + kind.__name__.lower()}}) + "\\n")
    sys.stdout.flush()
sys.excepthook = safe_excepthook
payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
target = payload["target"]
host = urlsplit(target).hostname
if host == "timeout.example.test":
    time.sleep(20)
if host == "oversize.example.test":
    sys.stdout.write("x" * 40000 + "\\n")
    sys.stdout.flush()
    time.sleep(5)
    raise SystemExit(0)
if host == "partial.example.test":
    sys.stdout.write("not-json\\n")
    raise SystemExit(0)
if host == "failure.example.test":
    sys.stdout.write('{{"ok":false,"error":"fixture_failure"}}\\n')
    raise SystemExit(2)
result = json.loads({result_literal})
result["input_url"] = target
result["final_url"] = target
if host == "security.example.test":
    try:
        result["notes"] = ["child_uid=" + str(os.geteuid()), "secret_env_present=" + str("CT_SCAN_SECRET_FILE" in os.environ).lower()]
        with open({str(self.secret)!r}, "rb") as handle:
            handle.read()
        result["notes"].append("secret_file=readable")
    except PermissionError:
        result["notes"].append("secret_file=denied")
    except OSError:
        result["notes"].append("secret_file=unavailable")
    except BaseException as exc:
        sys.stdout.write(json.dumps({{"ok":False,"error":"fixture_" + type(exc).__name__.lower()}}) + "\\n")
        raise SystemExit(2)
if host == "admit.example.test":
    channel = socket.socket(fileno=int(os.environ["CT_ADMISSION_FD"]))
    channel.sendall(b'{{"op":"admit","kind":"http","n":1}}\\n')
    reply = b""
    while not reply.endswith(b"\\n"):
        reply += channel.recv(64)
    channel.sendall(b'{{"op":"done","n":1}}\\n')
    result["notes"] = ["child_uid=" + str(os.geteuid()), "admission_ok=" + str(json.loads(reply)["ok"]).lower()]
sys.stdout.write(json.dumps({{"ok":True,"result":result}}, separators=(",", ":")) + "\\n")
'''
        scanner = worker / "scanner.py"
        scanner.write_text(script, encoding="utf-8")
        scanner.chmod(0o755)
        for path in (integrations / "__init__.py", worker / "__init__.py"):
            path.chmod(0o644)
        self.runner = SubprocessRunner(repo_root=str(root))

    def test_child_is_unprivileged_has_no_secret_env_or_key_access(self):
        with mock.patch.dict(os.environ, {"CT_SCAN_SECRET_FILE": str(self.secret)}):
            result = self.runner.run("https://security.example.test/", timeout=5, gate=_UnusedGate())
        self.assertIn("child_uid=65534", result["notes"])
        self.assertIn("secret_env_present=false", result["notes"])
        self.assertIn("secret_file=denied", result["notes"])

    def test_unprivileged_child_can_ask_the_supervisor_for_admission_over_the_inherited_socket(self):
        from integrations.worker.admission import Grant

        class Gate:
            admits = 0

            def admit(self):
                Gate.admits += 1
                return Grant(1, 1.0, 10.0, 19)

            def probe(self):
                return None

        result = self.runner.run("https://admit.example.test/", timeout=5, gate=Gate())
        self.assertIn("child_uid=65534", result["notes"])
        self.assertIn("admission_ok=true", result["notes"])
        self.assertEqual(Gate.admits, 1)

    def test_parent_kills_child_at_deadline_and_caps_stdout(self):
        started = time.monotonic()
        with self.assertRaises(ScannerFailure) as timeout:
            self.runner.run("https://timeout.example.test/", timeout=0.35, gate=_UnusedGate())
        self.assertEqual(timeout.exception.slug, "scanner_timeout")
        self.assertLess(time.monotonic() - started, 2.0)
        with self.assertRaises(ScannerFailure) as overflow:
            self.runner.run("https://oversize.example.test/", timeout=5, gate=_UnusedGate())
        self.assertEqual(overflow.exception.slug, "scanner_output_overflow")

    def test_child_failure_and_partial_output_are_not_interpreted_as_results(self):
        with self.assertRaises(ScannerFailure) as failure:
            self.runner.run("https://failure.example.test/", timeout=5, gate=_UnusedGate())
        self.assertEqual(failure.exception.slug, "fixture_failure")
        with self.assertRaises(ScannerFailure) as partial:
            self.runner.run("https://partial.example.test/", timeout=5, gate=_UnusedGate())
        self.assertEqual(partial.exception.slug, "scanner_invalid_output")


if __name__ == "__main__":
    unittest.main()
