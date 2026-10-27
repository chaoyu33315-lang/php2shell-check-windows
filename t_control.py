"""Offline tests for exact-target control checks (DNS TXT and HTTPS file).

Only local sockets and servers are used; no external host or resolver is contacted.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from integrations.worker import admission, control, network
from integrations.worker.admission import AdmissionDenied, AdmissionGate, AdmissionRefused, Grant
from integrations.worker.control import ControlError, build_txt_query, fetch_challenge_file, lookup_txt, parse_txt_response
from integrations.worker.network import PinnedOpener
from integrations.worker.protocol import APIClient, APIError, ControlTask, validate_control_task
from integrations.worker.runner import ScannerFailure, SubprocessRunner
from integrations.worker.service import WorkerService
from integrations.worker.spool import DurableSpool

from test_scan_worker import REVISION, TARGET, _FakeAPI

NOW = 1_800_000_000
HOST = "example.test"
NAME = "_ct-scan-challenge.example.test"
TOKEN = "ab" * 32


def _name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def txt_rdata(*strings: bytes) -> bytes:
    return b"".join(bytes([len(item)]) + item for item in strings)


def dns_response(txid, answers=(), *, flags=0x8180, name=NAME, qtype=16, extra_header=None, compress=True):
    """A TXT answer packet. ``answers`` are (rtype, rclass, rdata) triples."""
    header = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0)
    question = _name(name) + struct.pack("!HH", qtype, 1)
    body = b""
    for rtype, rclass, rdata in answers:
        owner = b"\xc0\x0c" if compress else _name(name)
        body += owner + struct.pack("!HHIH", rtype, rclass, 60, len(rdata)) + rdata
    return header + question + body


class ParseTests(unittest.TestCase):
    def test_query_is_one_recursive_txt_question(self):
        packet = build_txt_query(NAME, 0x1234)
        self.assertEqual(packet[:12], struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(packet[12:], _name(NAME) + struct.pack("!HH", 16, 1))
        for bad in ("a" * 64 + ".example.test", ".".join(["a" * 60] * 5), "café.example.test"):
            with self.subTest(bad=bad[:20]), self.assertRaises((ControlError, UnicodeEncodeError)):
                build_txt_query(bad, 1)

    def test_values_multiple_strings_are_concatenated_and_other_records_ignored(self):
        packet = dns_response(7, [
            (16, 1, txt_rdata(b"ct-scan-verify=", TOKEN.encode())),
            (1, 1, b"\x01\x02\x03\x04"),
            (16, 1, txt_rdata(b"v=spf1 -all")),
            (16, 3, txt_rdata(b"wrong class")),
        ])
        self.assertEqual(parse_txt_response(packet, 7, NAME), ["ct-scan-verify=" + TOKEN, "v=spf1 -all"])
        self.assertEqual(parse_txt_response(dns_response(7, [(16, 1, txt_rdata(b"x"))], compress=False), 7, NAME), ["x"])
        self.assertEqual(parse_txt_response(dns_response(7, [], flags=0x8183), 7, NAME), [], "NXDOMAIN is simply not found")
        self.assertEqual(parse_txt_response(dns_response(7, []), 7, NAME), [])

    def test_untrustworthy_answers_are_errors_not_values(self):
        good = dns_response(9, [(16, 1, txt_rdata(b"x"))])
        cases = {
            "wrong id": parse_args(dns_response(10, [(16, 1, txt_rdata(b"x"))]), 9),
            "not a response": parse_args(dns_response(9, [], flags=0x0100), 9),
            "truncated flag": parse_args(dns_response(9, [], flags=0x8380), 9),
            "servfail": parse_args(dns_response(9, [], flags=0x8182), 9),
            "refused": parse_args(dns_response(9, [], flags=0x8185), 9),
            "other question": parse_args(dns_response(9, [(16, 1, txt_rdata(b"x"))], name="_ct-scan-challenge.other.test"), 9),
            "wrong type": parse_args(dns_response(9, [], qtype=1), 9),
            "short": parse_args(b"\x00" * 5, 9),
            "empty": parse_args(b"", 9),
            "cut mid-record": parse_args(good[:-3], 9),
            "oversize": parse_args(good + b"\x00" * 5000, 9),
            "bad string length": parse_args(dns_response(9, [(16, 1, b"\x09ab")]), 9),
            "compression loop": parse_args(dns_response(9, [], name=NAME)[:12] + b"\xc0\x0c" + struct.pack("!HH", 16, 1), 9),
            "pointer past end": parse_args(dns_response(9, [], name=NAME)[:12] + b"\xc0\xff" + struct.pack("!HH", 16, 1), 9),
            "reserved label bits": parse_args(dns_response(9, [], name=NAME)[:12] + b"\x80" + b"\x00" * 6, 9),
            "non-bytes": parse_args("text", 9),
        }
        for label, args in cases.items():
            with self.subTest(label), self.assertRaises(ControlError):
                parse_txt_response(*args)

    def test_record_count_and_size_are_bounded(self):
        many = dns_response(3, [(16, 1, txt_rdata(b"v%d" % i)) for i in range(9)])
        with self.assertRaises(ControlError):
            parse_txt_response(many, 3, NAME)
        big = dns_response(3, [(16, 1, txt_rdata(b"a" * 255, b"b" * 255)) for _ in range(7)])
        self.assertLessEqual(len(big), control.MAX_BYTES)
        self.assertEqual(len(parse_txt_response(big, 3, NAME)), 7)
        wide = dns_response(3, [(16, 1, txt_rdata(*[b"c" * 255] * 4)) for _ in range(4)] + [(16, 1, txt_rdata(*[b"d" * 255] * 4))])
        with self.assertRaises(ControlError):  # 5 x 1020 bytes of text
            parse_txt_response(wide, 3, NAME)

    def test_resolver_comes_from_the_first_nameserver_line_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolv.conf"
            path.write_text("# c\nsearch evil.test\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n", encoding="ascii")
            self.assertEqual(control.system_resolver(str(path)), ("192.0.2.53", 53))
            path.write_text("search only\n", encoding="ascii")
            with self.assertRaises(ControlError):
                control.system_resolver(str(path))
            with self.assertRaises(ControlError):
                control.system_resolver(str(Path(directory) / "missing"))


def parse_args(packet, txid):
    return (packet, txid, NAME)


class _Guard:
    def __init__(self, allow=1, stale=False):
        self.allow, self.stale, self.events = allow, stale, []

    def admit(self):
        self.events.append("admit")
        if self.allow <= 0:
            raise AdmissionRefused("job_cancelled")
        self.allow -= 1

    def ensure_fresh(self):
        self.events.append("fresh")
        if self.stale:
            raise AdmissionRefused("admission_expired")

    def done(self):
        self.events.append("done")


class FakeDNS:
    """Loopback UDP DNS server. ``respond`` maps the request packet to a list of reply packets."""

    def __init__(self, test, respond):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self.respond = respond
        self.stop = threading.Event()
        thread = threading.Thread(target=self.loop, daemon=True)
        thread.start()
        test.addCleanup(thread.join, 2)
        test.addCleanup(self.sock.close)
        test.addCleanup(self.stop.set)

    def loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.requests.append(data)
            for reply in self.respond(data, addr) or []:
                self.sock.sendto(reply, addr)


def echo_txid(data):
    return struct.unpack("!H", data[:2])[0]


class LookupTests(unittest.TestCase):
    def test_one_admitted_query_returns_the_published_value(self):
        server = FakeDNS(self, lambda d, a: [dns_response(echo_txid(d), [(16, 1, txt_rdata(b"ct-scan-verify=" + TOKEN.encode()))])])
        guard = _Guard()
        values = lookup_txt(HOST, ("127.0.0.1", server.port), guard, timeout=2)
        self.assertEqual(values, ["ct-scan-verify=" + TOKEN])
        self.assertEqual(guard.events, ["admit", "fresh", "done"])
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(server.requests[0][12:], _name(NAME) + struct.pack("!HH", 16, 1))

    def test_refused_or_stale_admission_sends_no_query(self):
        server = FakeDNS(self, lambda d, a: [])
        with self.assertRaises(AdmissionRefused):
            lookup_txt(HOST, ("127.0.0.1", server.port), _Guard(allow=0), timeout=1)
        stale = _Guard(stale=True)
        with self.assertRaises(AdmissionRefused):
            lookup_txt(HOST, ("127.0.0.1", server.port), stale, timeout=1)
        time.sleep(0.3)
        self.assertEqual(server.requests, [])
        self.assertEqual(stale.events, ["admit", "fresh", "done"])

    def test_forged_replies_from_elsewhere_or_with_another_id_are_not_trusted(self):
        forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(forger.close)
        forger.bind(("127.0.0.1", 0))

        def respond(data, client):
            txid = echo_txid(data)
            # A packet from a different source port arrives first; then a wrong id; then the real answer.
            forger.sendto(dns_response(txid, [(16, 1, txt_rdata(b"forged"))]), client)
            return [dns_response(txid ^ 1, [(16, 1, txt_rdata(b"wrong-id"))]), dns_response(txid, [(16, 1, txt_rdata(b"real"))])]

        server = FakeDNS(self, respond)
        guard = _Guard()
        with self.assertRaises(ControlError) as wrong:
            lookup_txt(HOST, ("127.0.0.1", server.port), guard, timeout=2)
        self.assertEqual(str(wrong.exception), "dns_mismatch", "a wrong-id reply from the resolver must fail, not be skipped")
        self.assertEqual(guard.events, ["admit", "fresh", "done"])

    def test_silence_times_out_once_and_never_retries(self):
        server = FakeDNS(self, lambda d, a: [])
        guard = _Guard()
        with self.assertRaises(ControlError) as timeout:
            lookup_txt(HOST, ("127.0.0.1", server.port), guard, timeout=0.3)
        self.assertEqual(str(timeout.exception), "dns_timeout")
        time.sleep(0.3)
        self.assertEqual(len(server.requests), 1)
        self.assertEqual(guard.events[-1], "done")

    def test_truncated_answer_is_an_error_without_a_tcp_fallback(self):
        server = FakeDNS(self, lambda d, a: [dns_response(echo_txid(d), [], flags=0x8380)])
        with self.assertRaises(ControlError) as truncated:
            lookup_txt(HOST, ("127.0.0.1", server.port), _Guard(), timeout=2)
        self.assertEqual(str(truncated.exception), "dns_truncated")


class _LocalScope:
    def __init__(self, port):
        self.port = port

    def validate_request(self, url):
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != HOST:
            raise ValueError("request_out_of_scope")
        return "http", self.port, HOST, urlunsplit(("", "", parts.path or "/", parts.query, ""))


class _PlainAsHTTPS(network.PinnedHTTPConnection):
    """Test double: speak plain HTTP to the loopback fixture where production uses TLS."""

    def __init__(self, host, port, *, context=None, **kwargs):
        super().__init__(host, port, **kwargs)


class FileTests(unittest.TestCase):
    def serve(self, status=200, body=b"", headers=None, delay=0.0):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, dict(self.headers)))
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(status)
                    for key, value in (headers or {}).items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *_args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_port, seen

    def fetch(self, port, guard, timeout=2):
        opener = PinnedOpener(_LocalScope(port), guard=guard)
        with mock.patch.object(network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]), mock.patch.object(network, "PinnedHTTPSConnection", _PlainAsHTTPS):
            return fetch_challenge_file(opener, HOST, timeout)

    def test_the_fixed_path_is_requested_once_with_a_descriptive_agent(self):
        port, seen = self.serve(body=TOKEN.encode() + b"\n")
        guard = _Guard()
        self.assertEqual(self.fetch(port, guard), ("observed", [TOKEN + "\n"]))
        self.assertEqual([path for path, _h in seen], ["/.well-known/ct-scan-challenge.txt"])
        self.assertIn("php2shell-check-control", {k.lower(): v for k, v in seen[0][1].items()}["user-agent"])
        self.assertEqual(guard.events, ["admit", "fresh", "done"])

    def test_redirects_are_not_followed_and_are_not_found(self):
        for status in (301, 302, 307, 308):
            with self.subTest(status=status):
                port, seen = self.serve(status=status, headers={"Location": "https://attacker.example.test/ct-scan-challenge.txt"})
                self.assertEqual(self.fetch(port, _Guard()), ("not_found", []))
                self.assertEqual(len(seen), 1)

    def test_status_mapping(self):
        for status, expected in ((404, "not_found"), (410, "not_found"), (500, "error"), (403, "error"), (429, "error"), (204, "error")):
            with self.subTest(status=status):
                port, _seen = self.serve(status=status, body=b"")
                self.assertEqual(self.fetch(port, _Guard())[0], expected)

    def test_size_limit_and_encoding(self):
        port, _ = self.serve(body=b"a" * 4096)
        self.assertEqual(self.fetch(port, _Guard())[0], "observed")
        port, _ = self.serve(body=b"a" * 4097)
        self.assertEqual(self.fetch(port, _Guard()), ("error", []), "an oversized body is never partially accepted")
        port, _ = self.serve(body=b"\xff\xfe" + TOKEN.encode())
        self.assertEqual(self.fetch(port, _Guard()), ("error", []))

    def test_slow_server_times_out_without_a_second_request(self):
        port, seen = self.serve(body=b"x", delay=1.5)
        started = time.monotonic()
        self.assertEqual(self.fetch(port, _Guard(), timeout=0.3), ("error", []))
        self.assertLess(time.monotonic() - started, 1.4)
        self.assertEqual(len(seen), 1)

    def test_refused_admission_reaches_nothing(self):
        port, seen = self.serve(body=TOKEN.encode())
        with self.assertRaises(AdmissionRefused):
            self.fetch(port, _Guard(allow=0))
        self.assertEqual(seen, [])

    def test_a_private_destination_is_refused_before_any_connection(self):
        scope = network.RequestOrigin.from_target("https://example.test/")[0]
        guard = _Guard()
        opener = PinnedOpener(scope, guard=guard)
        with mock.patch.object(network, "_public_addresses", side_effect=ValueError("non_public_address")):
            self.assertEqual(fetch_challenge_file(opener, "example.test"), ("error", []))
        self.assertEqual(guard.events, [], "no admission is spent on an unsafe destination")
        # And another host can never be reached through the same opener.
        self.assertEqual(fetch_challenge_file(opener, "attacker.example.test"), ("error", []))


class ProtocolTests(unittest.TestCase):
    def payload(self, **overrides):
        data = {"id": 5, "target": TARGET, "scope_hash": __import__("hashlib").sha256(TARGET.encode()).hexdigest(), "method": "dns_txt", "expires_at": NOW + 7200, "lease": "l" * 64, "lease_until": NOW + 100}
        data.update(overrides)
        return {"task": data}

    def test_task_validation_reuses_the_claim_rules(self):
        now = datetime.fromtimestamp(NOW, timezone.utc)
        task = validate_control_task(self.payload(), now=now)
        self.assertIsInstance(task, ControlTask)
        self.assertEqual((task.job_id, task.method, task.target), (5, "dns_txt", TARGET))
        self.assertIsNone(validate_control_task({"task": None}, now=now))
        bad = [
            {}, {"task": 5}, {"task": {}}, self.payload(method="http"), self.payload(method=None), self.payload(target="https://other.example.test/"),
            self.payload(scope_hash="0" * 64), self.payload(lease="short"), self.payload(expires_at=NOW - 1), self.payload(lease_until=NOW + 99999),
            self.payload(id=True), self.payload(id=0), {"task": dict(self.payload()["task"], extra=1)}, {"task": None, "x": 1},
        ]
        for value in bad:
            with self.subTest(value=str(value)[:60]), self.assertRaises(APIError):
                validate_control_task(value, now=now)

    def test_requests_are_signed_for_their_own_routes(self):
        captured = []

        class Transport:
            def open(self, request, timeout):
                from test_scan_worker import _Response

                captured.append((request.full_url, json.loads(request.data), timeout))
                return _Response(json.dumps({"task": None} if request.full_url.endswith("claim") else {"ok": True, "verified": False}).encode())

        client = APIClient(b"s" * 32, transport=Transport(), clock=lambda: NOW)
        self.assertIsNone(client.control_claim())
        task = ControlTask(5, TARGET, "h" * 64, "https_file", datetime.fromtimestamp(NOW + 100, timezone.utc), "l" * 64, datetime.fromtimestamp(NOW + 50, timezone.utc))
        self.assertEqual(client.control_result(task, "not_found", []), {"ok": True, "verified": False})
        self.assertEqual(captured[0][0], "https://complete.tech/wp-json/ct-scan/v1/control/claim")
        self.assertEqual(captured[1][0], "https://complete.tech/wp-json/ct-scan/v1/control/result")
        self.assertEqual(captured[1][1], {"id": 5, "lease": "l" * 64, "scope_hash": "h" * 64, "method": "https_file", "outcome": "not_found", "observed": []})
        for outcome, observed in (("verified", []), ("observed", "text"), (None, [])):
            with self.subTest(outcome=outcome), self.assertRaises(APIError):
                client.control_result(task, outcome, observed)
        for kind in ("control", "control_probe"):
            client.admit(task, kind)
        self.assertEqual([c[1]["kind"] for c in captured[-2:]], ["control", "control_probe"])


class GateKindTests(unittest.TestCase):
    def test_control_gate_asks_for_control_admissions_and_probes(self):
        calls = []

        class API:
            def admit(self, claim, kind):
                calls.append(kind)
                if kind == "control_probe":
                    return {"ok": True, "live": True}
                return {"ok": True, "admitted": True, "sequence": 1, "valid_ms": 1000, "timeout_ms": 10000, "http_remaining": 2}

        task = ControlTask(5, TARGET, "h" * 64, "dns_txt", datetime.fromtimestamp(NOW + 100, timezone.utc), "l" * 64, datetime.fromtimestamp(NOW + 50, timezone.utc))
        gate = AdmissionGate(API(), task, kind="control", clock=lambda: NOW)
        self.assertEqual(gate.admit().remaining, 2)
        gate.probe()
        self.assertEqual(calls, ["control", "control_probe"])
        with self.assertRaises(ValueError):
            AdmissionGate(API(), task, kind="tls")
        # A scanner may not ask for another kind than its run was started for.
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        pump = admission.AdmissionPump(parent, gate, kind="control")
        child.sendall(b'{"op":"admit","kind":"http","n":1}\n')
        time.sleep(0.05)
        self.assertEqual(pump.service(), "admission_protocol_violation")

    def test_an_already_admitted_lease_ends_the_check_without_retry(self):
        calls = []

        class API:
            def admit(self, claim, kind):
                calls.append(kind)
                if len(calls) == 1:
                    raise APIError("api_http_409", status=409, payload={"ok": False, "reason": "already_admitted"})
                return {"ok": True, "admitted": True, "sequence": 2, "valid_ms": 1000, "timeout_ms": 10000, "http_remaining": 1}

        task = ControlTask(5, TARGET, "h" * 64, "dns_txt", datetime.fromtimestamp(NOW + 100, timezone.utc), "l" * 64, datetime.fromtimestamp(NOW + 50, timezone.utc))
        gate = AdmissionGate(API(), task, kind="control", clock=lambda: NOW)
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "already_admitted")
        self.assertEqual(calls, ["control"], "an already admitted lease must not be retried into a second check")


@unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor uses Linux process isolation APIs")
class ScannerControlTests(unittest.TestCase):
    """The real scanner entry point, doing a DNS control check over a socket pair and a fake resolver."""

    def run_main(self, task, resolver_port=None, target="https://example.test/", grant=True):
        import io

        from integrations.worker import scanner

        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        fd = os.dup(child.fileno())
        child.close()
        seen = []

        def supervisor():
            while True:
                try:
                    data = parent.recv(256)
                except OSError:
                    return
                if not data:
                    return
                for line in data.split(b"\n"):
                    if not line:
                        continue
                    message = json.loads(line.decode())
                    seen.append(message)
                    if message["op"] == "admit":
                        reply = {"ok": True, "n": message["n"], "valid_ms": 900} if grant else {"ok": False, "n": message["n"], "reason": "job_cancelled"}
                        parent.sendall(json.dumps(reply).encode() + b"\n")

        thread = threading.Thread(target=supervisor, daemon=True)
        thread.start()
        stdout = io.BytesIO()

        class Out:
            buffer = stdout

        class In:
            buffer = io.BytesIO(json.dumps({"target": target, "task": task}).encode())

        patches = [
            mock.patch.object(scanner.os, "geteuid", return_value=65534),
            mock.patch.object(scanner.sys, "stdin", In),
            mock.patch.object(scanner.sys, "stdout", Out),
            mock.patch.dict(os.environ, {"CT_ADMISSION_FD": str(fd)}),
        ]
        if resolver_port is not None:
            patches.append(mock.patch.object(scanner, "system_resolver", return_value=("127.0.0.1", resolver_port)))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        code = scanner.main()
        thread.join(0.3)
        return code, json.loads(stdout.getvalue().decode()), seen

    def test_dns_check_reports_what_was_published_through_an_admitted_query(self):
        server = FakeDNS(self, lambda d, a: [dns_response(echo_txid(d), [(16, 1, txt_rdata(b"ct-scan-verify=" + TOKEN.encode()))])])
        code, output, seen = self.run_main("control_dns", server.port)
        self.assertEqual(code, 0)
        self.assertEqual(output, {"ok": True, "control": {"method": "dns_txt", "outcome": "observed", "observed": ["ct-scan-verify=" + TOKEN]}})
        self.assertEqual([m["op"] for m in seen], ["admit", "done"])
        self.assertEqual(seen[0]["kind"], "control")
        self.assertEqual(len(server.requests), 1)

    def test_not_found_and_resolver_errors_are_outcomes(self):
        server = FakeDNS(self, lambda d, a: [dns_response(echo_txid(d), [], flags=0x8183)])
        self.assertEqual(self.run_main("control_dns", server.port)[1]["control"], {"method": "dns_txt", "outcome": "not_found", "observed": []})
        server = FakeDNS(self, lambda d, a: [dns_response(echo_txid(d), [], flags=0x8182)])
        self.assertEqual(self.run_main("control_dns", server.port)[1]["control"]["outcome"], "error")

    def test_a_refused_admission_ends_the_run_and_sends_no_query(self):
        server = FakeDNS(self, lambda d, a: [])
        code, output, _seen = self.run_main("control_dns", server.port, grant=False)
        time.sleep(0.2)
        self.assertEqual((code, output), (2, {"ok": False, "error": "admission_job_cancelled"}))
        self.assertEqual(server.requests, [])

    def test_unknown_tasks_and_extra_input_are_refused(self):
        import io

        from integrations.worker import scanner

        for message in ({"target": "https://example.test/", "task": "scan_everything"}, {"target": "https://example.test/", "task": "control_dns", "x": 1}, {"task": "control_dns"}):
            stdout = io.BytesIO()

            class Out:
                buffer = stdout

            class In:
                buffer = io.BytesIO(json.dumps(message).encode())

            with mock.patch.object(scanner.os, "geteuid", return_value=65534), mock.patch.object(scanner.sys, "stdin", In), mock.patch.object(scanner.sys, "stdout", Out):
                self.assertEqual(scanner.main(), 2)
            self.assertEqual(json.loads(stdout.getvalue().decode()), {"ok": False, "error": "invalid_scanner_input"})


_CONTROL_CHILD = r'''
import json, os, socket, sys
from urllib.parse import urlsplit
from integrations.worker.admission import ChildAdmission, AdmissionRefused

payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
host = urlsplit(payload["target"]).hostname
task = payload["task"]
kind = "http" if host == "wrongkind.example.test" else "control"
guard = ChildAdmission(socket.socket(fileno=int(os.environ["CT_ADMISSION_FD"])), kind=kind)
try:
    guard.admit()
    guard.ensure_fresh()
    guard.done()
except AdmissionRefused:
    sys.stdout.write(json.dumps({"ok": False, "error": "fixture_refused"}) + "\n")
    raise SystemExit(2)
method = "dns_txt" if task == "control_dns" else "https_file"
control = {"method": method, "outcome": "observed", "observed": ["ct-scan-verify=x"]}
if host == "badoutcome.example.test":
    control["outcome"] = "verified"
if host == "toomany.example.test":
    control["observed"] = ["a"] * 9
if host == "wrongmethod.example.test":
    control["method"] = "https_file" if method == "dns_txt" else "dns_txt"
if host == "notfoundvalues.example.test":
    control["outcome"] = "not_found"
sys.stdout.write(json.dumps({"ok": True, "control": control}) + "\n")
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor uses Linux process isolation APIs")
class SupervisorControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        worker = root / "integrations" / "worker"
        worker.mkdir(parents=True)
        (root / "integrations" / "__init__.py").write_text("", encoding="utf-8")
        (worker / "__init__.py").write_text("", encoding="utf-8")
        real = Path(__file__).resolve().parent / "integrations" / "worker"
        for name in ("admission.py", "network.py", "protocol.py"):
            (worker / name).symlink_to(real / name)
        (worker / "scanner.py").write_text(_CONTROL_CHILD, encoding="utf-8")
        self.runner = SubprocessRunner(repo_root=str(root))
        for patch in (
            mock.patch("integrations.worker.runner.os.geteuid", return_value=0),
            mock.patch("integrations.worker.runner._has_kill_capability", return_value=True),
            mock.patch("integrations.worker.runner._linux_preexec_limits", lambda: None),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def gate(self):
        class G:
            admits = 0

            def admit(self_inner):
                G.admits += 1
                return Grant(1, 1.0, 10.0, 2)

            def probe(self_inner):
                return None

        return G()

    def test_a_control_run_is_admitted_once_and_returns_the_validated_outcome(self):
        gate = self.gate()
        control = self.runner.run("https://example.test/", timeout=10, gate=gate, task="control_dns")
        self.assertEqual(control, {"method": "dns_txt", "outcome": "observed", "observed": ["ct-scan-verify=x"]})
        self.assertEqual(type(gate).admits, 1)

    def test_malformed_control_output_is_rejected(self):
        for host in ("badoutcome", "toomany", "wrongmethod", "notfoundvalues"):
            with self.subTest(host=host), self.assertRaises(ScannerFailure) as failure:
                self.runner.run(f"https://{host}.example.test/", timeout=10, gate=self.gate(), task="control_https")
            self.assertEqual(failure.exception.slug, "scanner_result_schema")

    def test_a_scanner_cannot_borrow_another_admission_kind(self):
        with self.assertRaises(ScannerFailure) as failure:
            self.runner.run("https://wrongkind.example.test/", timeout=10, gate=self.gate(), task="control_dns")
        self.assertEqual(failure.exception.slug, "admission_protocol_violation")

    def test_unknown_tasks_never_start(self):
        with self.assertRaises(ScannerFailure) as failure:
            self.runner.run("https://example.test/", timeout=10, gate=self.gate(), task="shell")
        self.assertEqual(failure.exception.slug, "invalid_scanner_task")


class ServiceControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spool = DurableSpool(Path(self.temp.name) / "spool")
        self.spool.prepare()

    def task(self, method="dns_txt"):
        return ControlTask(5, TARGET, __import__("hashlib").sha256(TARGET.encode()).hexdigest(), method, datetime.fromtimestamp(NOW + 7200, timezone.utc), "l" * 64, datetime.fromtimestamp(NOW + 100, timezone.utc))

    def service(self, task, runner_behavior):
        class API(_FakeAPI):
            def __init__(self_inner):
                super().__init__()
                self_inner.results = []
                self_inner.claim_error = None

            def control_claim(self_inner):
                if self_inner.claim_error:
                    raise self_inner.claim_error
                return task

            def control_result(self_inner, claimed, outcome, observed):
                self_inner.results.append((claimed.job_id, claimed.method, outcome, observed))
                return {"ok": True}

        class Runner:
            calls = []

            def run(self_inner, target, *, timeout, stop_event=None, gate=None, task=None):
                Runner.calls.append((target, task, type(gate).__name__, gate.kind))
                return runner_behavior(target)

        api = API()
        self.runner = Runner
        return WorkerService(api, self.spool, Runner(), REVISION, clock=lambda: NOW), api

    def test_idle_when_no_check_is_due(self):
        service, api = self.service(None, lambda target: None)
        self.assertEqual(service.process_once(), "idle")
        self.assertEqual(api.results, [])

    def test_a_due_check_runs_once_with_a_control_gate_and_reports_its_outcome(self):
        service, api = self.service(self.task("https_file"), lambda target: {"method": "https_file", "outcome": "observed", "observed": [TOKEN]})
        self.assertEqual(service.process_once(), "control_observed")
        self.assertEqual(self.runner.calls, [(TARGET, "control_https", "AdmissionGate", "control")])
        self.assertEqual(api.results, [(5, "https_file", "observed", [TOKEN])])
        self.assertEqual(api.start_calls, [])

    def test_scanner_errors_are_reported_as_error_but_admission_failures_post_nothing(self):
        def boom(_target):
            raise ScannerFailure("scanner_timeout")

        service, api = self.service(self.task(), boom)
        self.assertEqual(service.process_once(), "control_error")
        self.assertEqual(api.results, [(5, "dns_txt", "error", [])])

        def cancelled(_target):
            raise ScannerFailure("admission_job_cancelled")

        service, api = self.service(self.task(), cancelled)
        self.assertEqual(service.process_once(), "control_admission_job_cancelled")
        self.assertEqual(api.results, [])

    def test_claim_failure_and_expired_task_do_nothing(self):
        service, api = self.service(self.task(), lambda target: None)
        api.claim_error = APIError("api_network_error")
        self.assertEqual(service.process_once(), "control_claim_failed_api_network_error")
        stale = ControlTask(5, TARGET, "h" * 64, "dns_txt", datetime.fromtimestamp(NOW + 1, timezone.utc), "l" * 64, datetime.fromtimestamp(NOW + 1, timezone.utc))
        service, api = self.service(stale, lambda target: None)
        self.assertEqual(service.process_once(), "control_stale")
        self.assertEqual(self.runner.calls, [])

    def test_a_failed_result_post_is_not_retried_into_another_check(self):
        service, api = self.service(self.task(), lambda target: {"method": "dns_txt", "outcome": "not_found", "observed": []})

        def failing(claimed, outcome, observed):
            raise APIError("api_http_410", status=410)

        api.control_result = failing
        self.assertEqual(service.process_once(), "control_result_failed_api_http_410")
        self.assertEqual(len(self.runner.calls), 1)


if __name__ == "__main__":
    unittest.main()
