"""Offline tests for the per-request admission guard.

Everything here talks only to local disposable servers and socket pairs. No
external website is contacted. The supervisor tests run a real child process
and a local HTTP fixture; they patch the root/privilege checks (the isolation
itself is covered by the root-only tests in test_scan_worker.py).
"""

from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.request import Request

from integrations.worker import admission, network
from integrations.worker.admission import (
    AdmissionDenied,
    AdmissionGate,
    AdmissionPump,
    AdmissionRefused,
    ChildAdmission,
    Grant,
    parse_grant,
    parse_refusal,
)
from integrations.worker.network import PinnedOpener, RequestOrigin
from integrations.worker.protocol import APIClient, APIError
from integrations.worker.runner import ScannerFailure, SubprocessRunner
from integrations.worker.service import WorkerService
from integrations.worker.spool import DurableSpool

from test_scan_worker import REVISION, TARGET, _FakeAPI, _claim, _result

NOW = 1_800_000_000
GRANT = {"ok": True, "admitted": True, "sequence": 1, "valid_ms": 1000, "timeout_ms": 10000, "http_remaining": 19}
REPO_ROOT = Path(__file__).resolve().parent


def _refusal(status, reason, **extra):
    return APIError(f"api_http_{status}", status=status, payload={"ok": False, "reason": reason, **extra})


class _AdmitAPI:
    """Scripted WordPress admission route."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def admit(self, claim, kind):
        self.calls.append(kind)
        item = self.responses.pop(0) if self.responses else _refusal(410, "job_cancelled")
        if isinstance(item, Exception):
            raise item
        return item


class _FakeClockEvent:
    """Stand-in for threading.Event whose wait() advances a fake monotonic clock."""

    def __init__(self, clock):
        self.clock = clock
        self.set_flag = False

    def is_set(self):
        return self.set_flag

    def wait(self, seconds):
        self.clock.now += seconds
        return self.set_flag


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class GrantParsingTests(unittest.TestCase):
    def test_valid_grant_is_clamped_to_the_disclosed_bounds(self):
        grant = parse_grant(dict(GRANT, valid_ms=60000, timeout_ms=600000))
        self.assertEqual((grant.valid_seconds, grant.timeout_seconds, grant.sequence, grant.remaining), (1.0, 10.0, 1, 19))

    def test_malformed_grants_are_refusals(self):
        bad = [
            None,
            [],
            {},
            dict(GRANT, ok=False),
            dict(GRANT, admitted=False),
            dict(GRANT, ok=1),
            dict(GRANT, extra=True),
            {k: v for k, v in GRANT.items() if k != "sequence"},
            dict(GRANT, sequence=True),
            dict(GRANT, sequence="1"),
            dict(GRANT, sequence=0),
            dict(GRANT, valid_ms=0),
            dict(GRANT, timeout_ms=-5),
            dict(GRANT, http_remaining=-1),
            dict(GRANT, valid_ms=1.5),
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(AdmissionDenied):
                parse_grant(value)

    def test_refusal_reasons_are_sanitized_and_default_to_unavailable(self):
        self.assertEqual(parse_refusal(_refusal(410, "job_cancelled")).slug, "job_cancelled")
        self.assertEqual(parse_refusal(APIError("api_http_500", status=500)).slug, "guard_unavailable")
        self.assertEqual(parse_refusal(_refusal(410, "Bad Reason; DROP")).slug, "guard_unavailable")
        self.assertEqual(parse_refusal(_refusal(429, "rate_wait", retry_after_ms=99999)).retry_after_ms, 1000)
        self.assertEqual(parse_refusal(_refusal(429, "rate_wait", retry_after_ms="soon")).retry_after_ms, 0)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.stop = _FakeClockEvent(self.clock)

    def gate(self, *responses, claim=None, wall=None):
        self.api = _AdmitAPI(*responses)
        return AdmissionGate(
            self.api,
            claim or _claim(expires_at=NOW + 7200),
            stop_event=self.stop,
            clock=wall or (lambda: NOW),
            monotonic=self.clock,
        )

    def test_grant_is_returned_for_exactly_one_call(self):
        grant = self.gate(GRANT).admit()
        self.assertIsInstance(grant, Grant)
        self.assertEqual(self.api.calls, ["http"])

    def test_cancellation_and_every_other_refusal_stop_immediately_without_retry(self):
        for reason in ("job_cancelled", "job_expired", "authorization_revoked_or_expired", "budget_exhausted", "lease_invalid_or_expired", "profile_unknown", "recipient_unconfirmed", "clock_anomaly"):
            with self.subTest(reason=reason):
                gate = self.gate(_refusal(410, reason), GRANT)
                with self.assertRaises(AdmissionDenied) as denied:
                    gate.admit()
                self.assertEqual(denied.exception.slug, reason)
                self.assertEqual(self.api.calls, ["http"], "a refusal must not be retried into a grant")

    def test_unavailable_store_or_garbled_answers_fail_closed(self):
        cases = [
            APIError("api_network_error"),
            APIError("api_http_500", status=500),
            APIError("api_http_503", status=503, payload="not a dict"),
            APIError("invalid_api_response", status=200),
            {"ok": True},
        ]
        for case in cases:
            with self.subTest(case=repr(case)):
                with self.assertRaises(AdmissionDenied):
                    self.gate(case).admit()

    def test_pacing_waits_are_bounded_and_then_grant(self):
        grant = self.gate(_refusal(429, "rate_wait", retry_after_ms=400), _refusal(429, "rate_wait", retry_after_ms=300), GRANT).admit()
        self.assertEqual(self.api.calls, ["http", "http", "http"])
        self.assertAlmostEqual(self.clock.now - 1000.0, 0.7, places=3)
        self.assertEqual(grant.sequence, 1)

    def test_endless_pacing_or_busy_answers_end_in_a_refusal(self):
        for refusal in (_refusal(429, "rate_wait", retry_after_ms=1000), _refusal(503, "queue_busy")):
            with self.subTest(refusal=refusal.payload["reason"]):
                self.clock.now = 1000.0
                gate = self.gate(*([refusal] * 100))
                with self.assertRaises(AdmissionDenied):
                    gate.admit()
                self.assertLess(len(self.api.calls), 100)
                self.assertLessEqual(self.clock.now - 1000.0, admission.MAX_ADMIT_WAIT_SECONDS + 1.1)

    def test_a_grant_that_came_back_too_slowly_is_discarded_and_asked_for_again(self):
        slow = [0.7, 0.7]

        class SlowAPI(_AdmitAPI):
            def admit(inner, claim, kind):
                if slow:
                    self.clock.now += slow.pop(0)
                return super().admit(claim, kind)

        self.api = SlowAPI(GRANT, dict(GRANT, sequence=2), dict(GRANT, sequence=3))
        gate = AdmissionGate(self.api, _claim(expires_at=NOW + 7200), stop_event=self.stop, clock=lambda: NOW, monotonic=self.clock)
        grant = gate.admit()
        self.assertEqual(grant.sequence, 3, "the two slow slots are spent, the third is delivered")
        self.assertEqual(self.api.calls, ["http", "http", "http"])
        # Persistently slow: refused rather than delivering a grant with no lifetime left.
        slow.extend([0.7] * 5)
        self.api = SlowAPI(*([GRANT] * 5))
        gate = AdmissionGate(self.api, _claim(expires_at=NOW + 7200), stop_event=self.stop, clock=lambda: NOW, monotonic=self.clock)
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "admission_expired")
        self.assertEqual(len(self.api.calls), 3)

    def test_slow_regrants_stop_at_the_admission_deadline(self):
        class SlowAPI(_AdmitAPI):
            def admit(inner, claim, kind):
                self.clock.now += 2.5
                return super().admit(claim, kind)

        self.api = SlowAPI(*([GRANT] * 5))
        gate = AdmissionGate(self.api, _claim(expires_at=NOW + 7200), stop_event=self.stop, clock=lambda: NOW, monotonic=self.clock)
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "admission_expired")
        # The second slow answer lands past the four-second deadline: no third ask.
        self.assertEqual(len(self.api.calls), 2)
        self.assertLessEqual(self.clock.now - 1000.0, admission.MAX_ADMIT_WAIT_SECONDS + admission.CALL_BUDGET_SECONDS)

    def test_no_admission_is_requested_after_the_scan_deadline(self):
        gate = AdmissionGate(_AdmitAPI(GRANT), _claim(expires_at=NOW + 7200), deadline=NOW - 1, clock=lambda: NOW, monotonic=self.clock)
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "scan_deadline")

    def test_shutdown_interrupts_a_slow_guard_call(self):
        release = threading.Event()

        class Hang:
            def admit(self_inner, claim, kind):
                release.wait(5)

        stop = threading.Event()
        gate = AdmissionGate(Hang(), _claim(expires_at=NOW + 7200), stop_event=stop, clock=lambda: NOW)
        threading.Timer(0.2, stop.set).start()
        started = time.monotonic()
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        release.set()
        self.assertEqual(denied.exception.slug, "worker_shutdown")
        self.assertLess(time.monotonic() - started, 2.0)

    def test_expired_authorization_is_refused_locally_without_asking(self):
        gate = self.gate(GRANT, claim=_claim(expires_at=NOW - 1), wall=lambda: NOW)
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "authorization_expired")
        self.assertEqual(self.api.calls, [])

    def test_shutdown_is_refused_locally_and_interrupts_waits(self):
        gate = self.gate(GRANT)
        self.stop.set_flag = True
        with self.assertRaises(AdmissionDenied) as denied:
            gate.admit()
        self.assertEqual(denied.exception.slug, "worker_shutdown")
        self.assertEqual(self.api.calls, [])

    def test_probe_requires_an_exact_live_answer(self):
        self.gate({"ok": True, "live": True}).probe()
        self.assertEqual(self.api.calls, ["probe"])
        for bad in ({"ok": True}, {"ok": True, "live": False}, {"ok": True, "live": True, "x": 1}, {"ok": False, "live": True}):
            with self.subTest(bad=bad), self.assertRaises(AdmissionDenied):
                self.gate(bad).probe()
        with self.assertRaises(AdmissionDenied) as denied:
            self.gate(_refusal(410, "job_cancelled")).probe()
        self.assertEqual(denied.exception.slug, "job_cancelled")


    def test_probe_retries_a_busy_queue_lock_within_one_call_budget(self):
        self.gate(_refusal(503, "queue_busy"), _refusal(503, "queue_busy"), {"ok": True, "live": True}).probe()
        self.assertEqual(self.api.calls, ["probe", "probe", "probe"])
        self.clock.now = 1000.0
        gate = self.gate(*([_refusal(503, "queue_busy")] * 100))
        with self.assertRaises(AdmissionDenied) as denied:
            gate.probe()
        self.assertEqual(denied.exception.slug, "queue_busy")
        self.assertLess(len(self.api.calls), 100)
        self.assertLessEqual(self.clock.now - 1000.0, admission.CALL_BUDGET_SECONDS)
        # Only a busy lock is retried: an explicit refusal is reported at once.
        with self.assertRaises(AdmissionDenied) as denied:
            self.gate(_refusal(410, "authorization_revoked_or_expired"), {"ok": True, "live": True}).probe()
        self.assertEqual(denied.exception.slug, "authorization_revoked_or_expired")
        self.assertEqual(self.api.calls, ["probe"])

    def test_a_control_probe_retries_a_busy_queue_lock_on_its_own_route(self):
        self.api = _AdmitAPI(_refusal(503, "queue_busy"), {"ok": True, "live": True})
        gate = AdmissionGate(self.api, _claim(expires_at=NOW + 7200), kind="control", stop_event=self.stop, clock=lambda: NOW, monotonic=self.clock)
        gate.probe()
        self.assertEqual(self.api.calls, ["control_probe", "control_probe"])


class ApiClientAdmitTests(unittest.TestCase):
    def test_admit_is_signed_for_its_own_route_with_a_short_timeout_and_exact_body(self):
        captured = {}

        class Transport:
            def open(self, request, timeout):
                captured["url"] = request.full_url
                captured["body"] = request.data
                captured["timeout"] = timeout
                captured["headers"] = dict(request.header_items())
                from test_scan_worker import _Response

                return _Response(json.dumps(GRANT).encode())

        client = APIClient(b"s" * 32, transport=Transport(), clock=lambda: NOW, nonce_factory=lambda: "0" * 32)
        claim = _claim()
        self.assertEqual(client.admit(claim, "http"), GRANT)
        self.assertEqual(captured["url"], "https://complete.tech/wp-json/ct-scan/v1/admit")
        self.assertEqual(captured["timeout"], 5.0)
        self.assertEqual(json.loads(captured["body"]), {"id": claim.job_id, "lease": claim.lease, "scope_hash": claim.scope_hash, "kind": "http"})
        body_hash = hashlib.sha256(captured["body"]).hexdigest()
        import hmac

        canonical = f"{NOW}\n{'0' * 32}\nPOST\n/ct-scan/v1/admit\n{body_hash}".encode()
        self.assertEqual(captured["headers"]["X-ct-signature"], hmac.new(b"s" * 32, canonical, hashlib.sha256).hexdigest())

    def test_unknown_kinds_are_not_sent(self):
        client = APIClient(b"s" * 32, transport=mock.Mock())
        for kind in ("tls", "", None, "HTTP"):
            with self.subTest(kind=kind), self.assertRaises(APIError):
                client.admit(_claim(), kind)

    def test_non_success_answers_carry_the_parsed_refusal(self):
        class Transport:
            def open(self, request, timeout):
                from test_scan_worker import _Response

                return _Response(b'{"ok":false,"reason":"job_cancelled"}', code=410)

        client = APIClient(b"s" * 32, transport=Transport(), clock=lambda: NOW)
        with self.assertRaises(APIError) as error:
            client.admit(_claim(), "probe")
        self.assertEqual((error.exception.status, error.exception.payload), (410, {"ok": False, "reason": "job_cancelled"}))


class _PumpHarness:
    """Run the child end on a thread so the blocking request/reply protocol can be exercised."""

    def __init__(self, test, gate, monotonic=time.monotonic):
        self.parent, child = socket.socketpair()
        self.child = ChildAdmission(child, monotonic=monotonic)
        self.child_sock = child
        self.pump = AdmissionPump(self.parent, gate, monotonic=monotonic)
        test.addCleanup(self.parent.close)
        test.addCleanup(child.close)

    def child_admit(self):
        outcome = {}

        def run():
            try:
                self.child.admit()
                outcome["ok"] = True
            except AdmissionRefused as exc:
                outcome["refused"] = str(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3
        fatal = None
        while thread.is_alive() and time.monotonic() < deadline:
            readable = __import__("select").select([self.parent], [], [], 0.05)[0]
            if readable:
                fatal = self.pump.service()
        thread.join(2)
        return outcome, fatal


class _ScriptGate:
    def __init__(self, admit=None, probe=None):
        self._admit = list(admit or [])
        self._probe = list(probe or [])
        self.admits = 0
        self.probes = 0

    def admit(self):
        self.admits += 1
        item = self._admit.pop(0) if self._admit else AdmissionDenied("job_cancelled")
        if isinstance(item, Exception):
            raise item
        return item

    def probe(self):
        self.probes += 1
        item = self._probe.pop(0) if self._probe else None
        if isinstance(item, Exception):
            raise item


def _grant(timeout=10.0):
    return Grant(1, 1.0, timeout, 19)


class PumpStateMachineTests(unittest.TestCase):
    def test_admit_then_done_allows_the_next_admission(self):
        gate = _ScriptGate(admit=[_grant(), _grant()])
        harness = _PumpHarness(self, gate)
        outcome, fatal = harness.child_admit()
        self.assertEqual((outcome, fatal), ({"ok": True}, None))
        self.assertTrue(harness.pump.inflight)
        harness.child.ensure_fresh()
        harness.child.done()
        harness.pump.service() if __import__("select").select([harness.parent], [], [], 1)[0] else None
        self.assertFalse(harness.pump.inflight)
        outcome, fatal = harness.child_admit()
        self.assertEqual((outcome, fatal, gate.admits), ({"ok": True}, None, 2))

    def test_a_second_admission_while_one_is_outstanding_kills_the_scanner(self):
        harness = _PumpHarness(self, _ScriptGate(admit=[_grant(), _grant()]))
        self.assertEqual(harness.child_admit()[0], {"ok": True})
        harness.child_sock.sendall(b'{"op":"admit","kind":"http","n":2}\n')
        self.assertTrue(__import__("select").select([harness.parent], [], [], 1)[0])
        self.assertEqual(harness.pump.service(), "admission_protocol_violation")
        self.assertEqual(harness.pump.grants, 1)

    def test_malformed_messages_are_protocol_violations(self):
        for raw in (
            b"done\n",
            b'{"op":"done"}\n',
            b'{"op":"done","n":1}\n',
            b'{"op":"admit","kind":"http"}\n',
            b'{"op":"admit","kind":"tls","n":1}\n',
            b'{"op":"admit","kind":"http","n":1,"x":1}\n',
            b'{"op":"admit","kind":"http","n":2}\n',
            b'{"op":"admit","kind":"http","n":0}\n',
            b'{"op":"admit","kind":"http","n":true}\n',
            b'{"op":"admit","kind":"http","n":"1"}\n',
            b"[]\n",
            b"\xff\n",
            b"x" * 400 + b"\n",
            b"x" * 300,
        ):
            with self.subTest(raw=raw[:20]):
                harness = _PumpHarness(self, _ScriptGate(admit=[_grant()]))
                harness.child_sock.sendall(raw)
                __import__("select").select([harness.parent], [], [], 1)
                self.assertEqual(harness.pump.service(), "admission_protocol_violation")
                self.assertEqual(harness.pump.grants, 0)

    def test_refusal_is_delivered_to_the_scanner_and_is_fatal(self):
        gate = _ScriptGate(admit=[AdmissionDenied("job_cancelled")])
        harness = _PumpHarness(self, gate)
        outcome, fatal = harness.child_admit()
        self.assertEqual(outcome, {"refused": "job_cancelled"})
        self.assertEqual(fatal, "admission_job_cancelled")
        self.assertEqual(harness.pump.service(), "admission_job_cancelled", "a fatal pump stays fatal")

    def test_in_flight_deadline_is_enforced_by_the_supervisor(self):
        clock = _Clock()
        gate = _ScriptGate(admit=[_grant(timeout=10.0)])
        harness = _PumpHarness(self, gate, monotonic=clock)
        self.assertEqual(harness.child_admit()[0], {"ok": True})
        clock.now += 9.9
        self.assertIsNone(harness.pump.tick())
        clock.now += 0.2  # 10.1 s after the grant: the disclosed ten-second bound, with no extra grace
        self.assertEqual(harness.pump.tick(), "request_deadline_exceeded")
        self.assertEqual(admission.REQUEST_GRACE_SECONDS, 0.0)

    def test_probe_refusal_is_fatal_but_an_unreachable_guard_is_not_by_itself(self):
        self.assertLessEqual(admission.PROBE_INTERVAL_SECONDS, 2.0, "cancellation must be noticed within a couple of seconds")
        clock = _Clock()
        gate = _ScriptGate(probe=[AdmissionDenied("guard_unavailable"), AdmissionDenied("job_cancelled")])
        harness = _PumpHarness(self, gate, monotonic=clock)
        self.assertIsNone(harness.pump.tick(), "no probe before the interval")
        self.assertEqual(gate.probes, 0)
        clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
        self.assertIsNone(harness.pump.tick())
        harness.pump.wait_probe()
        self.assertIsNone(harness.pump.tick(), "an unreachable guard alone does not kill the admitted request")
        self.assertEqual(gate.probes, 1)
        clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
        harness.pump.tick()
        harness.pump.wait_probe()
        self.assertEqual(harness.pump.tick(), "admission_job_cancelled")

    def test_a_busy_or_failing_store_during_a_probe_does_not_kill_the_scan(self):
        # The supervisor's own admission can hold the no-wait queue lock while a probe runs.
        clock = _Clock()
        gate = _ScriptGate(
            admit=[_grant(), _grant()],
            probe=[AdmissionDenied("queue_busy"), AdmissionDenied("admission_error"), AdmissionDenied("authorization_revoked_or_expired")],
        )
        harness = _PumpHarness(self, gate, monotonic=clock)
        self.assertEqual(harness.child_admit()[0], {"ok": True})
        for _ in range(2):
            clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
            self.assertIsNone(harness.pump.tick())
            harness.pump.wait_probe()
            self.assertIsNone(harness.pump.tick(), "an inconclusive probe does not end the scan")
        harness.child.done()
        __import__("select").select([harness.parent], [], [], 1)
        self.assertIsNone(harness.pump.service())
        self.assertEqual(harness.child_admit(), ({"ok": True}, None), "the scan continues to its next admission")
        self.assertEqual(gate.probes, 2)
        # An explicit refusal from a later probe is still fatal.
        clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
        harness.pump.tick()
        harness.pump.wait_probe()
        self.assertEqual(harness.pump.tick(), "admission_authorization_revoked_or_expired")

    def test_a_disabled_integration_is_a_refusal_that_stops_the_scanner(self):
        clock = _Clock()
        gate = _ScriptGate(probe=[AdmissionDenied("integration_disabled")])
        harness = _PumpHarness(self, gate, monotonic=clock)
        clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
        harness.pump.tick()
        harness.pump.wait_probe()
        self.assertEqual(harness.pump.tick(), "admission_integration_disabled")
        down = parse_refusal(APIError("api_http_503", status=503, payload={"error": "ct_scan_disabled"}))
        self.assertEqual(down.slug, "integration_disabled")

    def test_a_slow_probe_never_blocks_the_in_flight_deadline(self):
        clock = _Clock()
        release = threading.Event()

        class Slow(_ScriptGate):
            def probe(self):
                release.wait(5)

        harness = _PumpHarness(self, Slow(admit=[_grant(timeout=10.0)]), monotonic=clock)
        self.assertEqual(harness.child_admit()[0], {"ok": True})
        clock.now += admission.PROBE_INTERVAL_SECONDS + 0.01
        started = time.monotonic()
        self.assertIsNone(harness.pump.tick())
        self.assertLess(time.monotonic() - started, 1.0, "tick() waited on the guard")
        clock.now += 20
        self.assertEqual(harness.pump.tick(), "request_deadline_exceeded")
        release.set()
        harness.pump.wait_probe()

    def test_a_grant_that_aged_past_its_lifetime_while_the_supervisor_waited_is_not_delivered(self):
        clock = _Clock()

        class Slow(_ScriptGate):
            def admit(self):
                clock.now += 1.5  # the guard call took longer than the grant lives
                return Grant(1, 1.0, 10.0, 19, issued_at=1000.0)

        harness = _PumpHarness(self, Slow(), monotonic=clock)
        outcome, fatal = harness.child_admit()
        self.assertEqual((outcome, fatal), ({"refused": "admission_expired"}, "admission_expired"))
        self.assertFalse(harness.pump.inflight)

    def test_unreachable_guard_fails_the_next_admission_closed(self):
        class Down(_ScriptGate):
            def admit(self):
                self.admits += 1
                raise AdmissionDenied("guard_unavailable")

        harness = _PumpHarness(self, Down())
        outcome, fatal = harness.child_admit()
        self.assertEqual((outcome, fatal), ({"refused": "guard_unavailable"}, "admission_guard_unavailable"))

    def test_a_guard_call_that_overruns_its_budget_is_a_refusal(self):
        release = threading.Event()

        class Hang:
            def admit(self, claim, kind):
                release.wait(5)

        gate = AdmissionGate(Hang(), _claim(expires_at=NOW + 7200), clock=lambda: NOW)
        with mock.patch.object(admission, "CALL_BUDGET_SECONDS", 0.1):
            with self.assertRaises(AdmissionDenied) as denied:
                gate.admit()
        release.set()
        self.assertEqual(denied.exception.slug, "guard_timeout")

    def test_peer_close_is_remembered_without_spinning(self):
        harness = _PumpHarness(self, _ScriptGate())
        harness.child_sock.close()
        self.assertIsNone(harness.pump.service())
        self.assertTrue(harness.pump.closed)


class NetworkDenylistTests(unittest.TestCase):
    """The destination check lists special-purpose ranges itself; it must not depend on the
    interpreter's ipaddress `is_*` properties, which differ between Python versions."""

    @staticmethod
    def _answer(text):
        family = socket.AF_INET6 if ":" in text else socket.AF_INET
        return (family, socket.SOCK_STREAM, 6, "", (text, 443))

    def _rejected(self, text):
        with self.assertRaises(ValueError):
            network._public_addresses("example.test", 443, resolver=lambda *_a, **_k: [self._answer(text)])

    def test_every_listed_range_is_refused_at_both_ends_and_in_the_middle(self):
        for net in network.DENIED_V4 + network.DENIED_V6:
            first, last = net[0], net[-1]
            middle = net[net.num_addresses // 2] if net.num_addresses > 2 else first
            for address in {first, last, middle}:
                with self.subTest(network=str(net), address=str(address)):
                    self._rejected(str(address))

    def test_the_list_alone_refuses_them_even_if_every_builtin_property_said_public(self):
        neutral = property(lambda self: False)
        patches = []
        for cls in (ipaddress.IPv4Address, ipaddress.IPv6Address):
            for name in ("is_private", "is_reserved", "is_multicast", "is_unspecified", "is_loopback", "is_link_local"):
                patches.append(mock.patch.object(cls, name, new=neutral))
            patches.append(mock.patch.object(cls, "is_global", new=property(lambda self: True)))
        patches.append(mock.patch.object(ipaddress.IPv6Address, "is_site_local", new=neutral))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        for text in ("100.64.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "10.1.2.3", "169.254.169.254", "0.0.0.1", "255.255.255.255",
                     "3fff::1", "3fff:fff:ffff:ffff::1", "2001:db8::1", "2002:808:808::", "64:ff9b::808:808", "100::1", "fc00::1", "fe80::1", "5f00::1"):
            with self.subTest(address=text):
                self._rejected(text)

    def test_neighbours_just_outside_each_range_are_not_swept_up(self):
        for text in ("100.63.255.255", "100.128.0.0", "198.17.255.255", "198.20.0.0", "192.0.3.0", "203.0.114.0", "3fff:1000::1", "2001:4860:4860::8888", "2606:4700:4700::1111"):
            with self.subTest(address=text):
                self.assertEqual(
                    network._public_addresses("example.test", 443, resolver=lambda *_a, **_k: [self._answer(text)]),
                    [(socket.AF_INET6 if ":" in text else socket.AF_INET, text)],
                )


class ChildAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.clock = _Clock()
        self.parent, self.child = socket.socketpair()
        self.addCleanup(self.parent.close)
        self.addCleanup(self.child.close)
        self.client = ChildAdmission(self.child, monotonic=self.clock)

    def reply(self, value, *, number=None):
        """Answer the next request. A dict gets the request's sequence number unless one is forced."""

        def run():
            request = json.loads(self.parent.recv(256).decode())
            if isinstance(value, dict):
                body = json.dumps(dict(value, n=request["n"] if number is None else number)).encode() + b"\n"
            else:
                body = value
            self.parent.sendall(body)

        threading.Thread(target=run, daemon=True).start()

    def test_connect_is_refused_without_a_grant_and_after_the_grant_goes_stale(self):
        with self.assertRaises(AdmissionRefused):
            self.client.ensure_fresh()
        self.reply({"ok": True, "valid_ms": 1000})
        self.client.admit()
        self.clock.now += 0.5
        self.client.ensure_fresh()
        self.clock.now += 0.6
        with self.assertRaises(AdmissionRefused) as stale:
            self.client.ensure_fresh()
        self.assertEqual(str(stale.exception), "admission_expired")

    def test_scanner_rejects_oversized_extended_or_garbled_replies(self):
        for raw in (
            {"ok": True, "valid_ms": 5000},
            {"ok": True, "valid_ms": 0},
            {"ok": True, "valid_ms": 1000, "x": 1},
            {"ok": True},
            b"not json\n",
            b"[]\n",
            b"x" * 400 + b"\n",
        ):
            with self.subTest(raw=raw if isinstance(raw, dict) else raw[:30]):
                parent, child = socket.socketpair()
                self.addCleanup(parent.close)
                client = ChildAdmission(child, monotonic=self.clock)
                self.parent, self.child = parent, child
                self.reply(raw)
                with self.assertRaises(AdmissionRefused):
                    client.admit()
                with self.assertRaises(AdmissionRefused):
                    client.ensure_fresh()

    def test_a_reply_for_another_request_is_never_taken_as_the_answer(self):
        # Desynchronisation: a stale grant arrives after the scanner gave up on its request.
        self.reply({"ok": True, "valid_ms": 1000}, number=7)
        with self.assertRaises(AdmissionRefused) as wrong:
            self.client.admit()
        self.assertEqual(str(wrong.exception), "admission_reply_invalid")
        with self.assertRaises(AdmissionRefused):
            self.client.admit()
        with self.assertRaises(AdmissionRefused):
            self.client.ensure_fresh()

    def test_a_late_reply_after_a_timeout_cannot_satisfy_the_next_request(self):
        timeline = iter([1000.0, 1100.0])

        def fake_monotonic():
            return next(timeline, 1100.0)

        client = ChildAdmission(self.child, monotonic=fake_monotonic)
        with self.assertRaises(AdmissionRefused) as timeout:
            client.admit()
        self.assertEqual(str(timeout.exception), "admission_timeout")
        try:
            self.parent.sendall(b'{"ok":true,"n":1,"valid_ms":1000}\n')  # the late answer
        except OSError:
            pass  # the poisoned scanner end is already closed: the answer has nowhere to land
        with self.assertRaises(AdmissionRefused):
            client.admit()
        with self.assertRaises(AdmissionRefused):
            client.ensure_fresh()

    def test_refusal_reason_is_surfaced_and_is_final(self):
        self.reply({"ok": False, "reason": "job_cancelled"})
        with self.assertRaises(AdmissionRefused) as refused:
            self.client.admit()
        self.assertEqual(str(refused.exception), "job_cancelled")
        with self.assertRaises(AdmissionRefused):
            self.client.admit()

    def test_a_closed_channel_refuses(self):
        self.parent.close()
        with self.assertRaises(AdmissionRefused):
            self.client.admit()

    def test_a_second_admission_before_done_is_refused_in_the_scanner(self):
        self.reply({"ok": True, "valid_ms": 1000})
        self.client.admit()
        with self.assertRaises(AdmissionRefused):
            self.client.admit()
        self.client.done()
        self.client.done()  # idempotent


class _LocalScope:
    def __init__(self, port):
        self.port = port

    def validate_request(self, url):
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname != "example.test":
            raise ValueError("request_out_of_scope")
        return "http", self.port, "example.test", urlunsplit(("", "", parts.path or "/", parts.query, ""))


class _Recorder:
    """Local disposable HTTP server that records every request it receives."""

    def __init__(self, test, delay=0.0):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((time.monotonic(), self.path))
                if delay and self.path == "/slow":
                    time.sleep(delay)
                body = b"<html><title>fixture</title></html>"
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *_args):
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        test.addCleanup(thread.join, 2)
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)


class _Guard:
    """Child-side guard double with the same surface as ChildAdmission."""

    def __init__(self, allow=1, stale=False):
        self.allow = allow
        self.stale = stale
        self.events = []

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


class OpenerGuardTests(unittest.TestCase):
    def open(self, guard, server):
        opener = PinnedOpener(_LocalScope(server.port), guard=guard)
        with mock.patch.object(network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]):
            return opener.open(Request("http://example.test/page"), timeout=2)

    def test_a_refused_admission_opens_no_connection(self):
        recorder = _Recorder(self)
        guard = _Guard(allow=0)
        with self.assertRaises(AdmissionRefused):
            self.open(guard, recorder)
        self.assertEqual(recorder.requests, [])
        self.assertEqual(guard.events, ["admit"], "nothing to report done for a refused admission")

    def test_a_stale_grant_is_not_used_to_connect_and_is_released(self):
        recorder = _Recorder(self)
        guard = _Guard(stale=True)
        with self.assertRaises(AdmissionRefused):
            self.open(guard, recorder)
        self.assertEqual(recorder.requests, [])
        self.assertEqual(guard.events, ["admit", "fresh", "done"])

    def test_one_grant_covers_one_request_and_done_follows_the_response(self):
        recorder = _Recorder(self)
        guard = _Guard(allow=2)
        with self.open(guard, recorder) as response:
            self.assertEqual(response.code, 200)
            self.assertEqual(guard.events, ["admit", "fresh"])
        self.assertEqual(guard.events, ["admit", "fresh", "done"])
        self.assertEqual(len(recorder.requests), 1)
        with self.open(guard, recorder):
            pass
        self.assertEqual(guard.events.count("admit"), 2)
        self.assertEqual(len(recorder.requests), 2)

    def test_connection_failure_still_reports_done_once(self):
        guard = _Guard()
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()  # nothing listens here
        opener = PinnedOpener(_LocalScope(port), guard=guard)
        with mock.patch.object(network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]):
            with self.assertRaises(OSError):
                opener.open(Request("http://example.test/page"), timeout=2)
        self.assertEqual(guard.events, ["admit", "fresh", "done"])

    def test_dns_or_scope_failures_never_spend_an_admission(self):
        guard = _Guard()
        scope, _ = RequestOrigin.from_target(TARGET)
        opener = PinnedOpener(scope, guard=guard)
        with self.assertRaises(ValueError):
            opener.open(Request("https://attacker.example.test/"))
        with mock.patch.object(network, "_public_addresses", side_effect=ValueError("non_public_address")):
            with self.assertRaises(ValueError):
                opener.open(Request(TARGET))
        self.assertEqual(guard.events, [])

    def test_checker_sends_nothing_when_admission_is_refused(self):
        from wordpress_check import Checker

        recorder = _Recorder(self)
        checker = Checker(timeout=2, delay=0)
        checker.opener = PinnedOpener(_LocalScope(recorder.port), guard=_Guard(allow=0))
        with mock.patch.object(network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]):
            # Not swallowed into an ordinary fetch error: the refusal ends the run.
            with self.assertRaises(AdmissionRefused):
                checker.check("http://example.test/")
        self.assertEqual(recorder.requests, [])


@unittest.skipUnless(sys.platform.startswith("linux"), "descriptor semantics differ outside Linux")
class ScannerChannelTests(unittest.TestCase):
    def test_scanner_has_no_channel_without_a_valid_unix_socket(self):
        from integrations.worker import scanner

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CT_ADMISSION_FD", None)
            self.assertIsNone(scanner._admission_channel())
        for bad in ("", "x", "-1", "0", "2", "99999", "7.5"):
            with self.subTest(bad=bad), mock.patch.dict(os.environ, {"CT_ADMISSION_FD": bad}):
                self.assertIsNone(scanner._admission_channel())
        tcp = socket.socket()
        self.addCleanup(tcp.close)
        duplicate = os.dup(tcp.fileno())
        self.assertGreaterEqual(duplicate, 3)
        with mock.patch.dict(os.environ, {"CT_ADMISSION_FD": str(duplicate)}):
            self.assertIsNone(scanner._admission_channel(), "a TCP socket is not the supervisor channel")


@unittest.skipUnless(sys.platform.startswith("linux"), "the scanner entry point requires Linux")
class ScannerMainTests(unittest.TestCase):
    """Drive the real scanner entry point, as the unprivileged child would run it."""

    def run_main(self, env, target="https://example.test/"):
        import io

        from integrations.worker import scanner

        stdout = io.BytesIO()

        class Out:
            buffer = stdout

        class In:
            buffer = io.BytesIO(json.dumps({"target": target}).encode())

        with mock.patch.object(scanner.os, "geteuid", return_value=65534), mock.patch.object(scanner.sys, "stdin", In), mock.patch.object(
            scanner.sys, "stdout", Out
        ), mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            network, "_public_addresses", return_value=[(socket.AF_INET, "127.0.0.1")]
        ):
            code = scanner.main()
        return code, json.loads(stdout.getvalue().decode())

    def test_without_the_supervisor_channel_the_scanner_refuses_to_scan(self):
        env = dict(os.environ)
        env.pop("CT_ADMISSION_FD", None)
        with mock.patch.dict(os.environ, env, clear=True):
            code, output = self.run_main({})
        self.assertEqual((code, output), (2, {"ok": False, "error": "admission_channel_unavailable"}))

    def test_a_refused_admission_ends_the_run_as_a_failure_not_a_result(self):
        parent, child = socket.socketpair()
        self.addCleanup(parent.close)
        fd = os.dup(child.fileno())
        child.close()

        def supervisor():
            request = json.loads(parent.recv(256).decode())
            parent.sendall(json.dumps({"ok": False, "n": request["n"], "reason": "job_cancelled"}).encode() + b"\n")

        thread = threading.Thread(target=supervisor, daemon=True)
        thread.start()
        code, output = self.run_main({"CT_ADMISSION_FD": str(fd)})
        thread.join(2)
        self.assertEqual((code, output), (2, {"ok": False, "error": "admission_job_cancelled"}))


# --- supervisor integration: a real child process, a local server, a flippable gate -----------

_CHILD_SCRIPT = r'''
import http.client, json, os, socket, sys, time
from urllib.parse import urlsplit
from integrations.worker.admission import ChildAdmission, AdmissionRefused

PORT = {port}
RESULT = {result!r}
payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
host = urlsplit(payload["target"]).hostname
guard = ChildAdmission(socket.socket(fileno=int(os.environ["CT_ADMISSION_FD"])))

def fetch(path):
    guard.admit()
    try:
        guard.ensure_fresh()
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        connection.request("GET", path)
        connection.getresponse().read()
        connection.close()
    finally:
        guard.done()

def finish():
    result = json.loads(RESULT)
    result["input_url"] = payload["target"]
    result["final_url"] = payload["target"]
    sys.stdout.write(json.dumps({{"ok": True, "result": result}}) + "\n")
    raise SystemExit(0)

try:
    if host == "three.example.test":
        for index in range(3):
            fetch("/r%d" % index)
        finish()
    if host == "slow.example.test":
        fetch("/slow")
        fetch("/after-slow")
        finish()
    if host == "backoff.example.test":
        fetch("/first")
        time.sleep(1.5)
        fetch("/second")
        finish()
    if host == "double.example.test":
        guard.admit()
        # A scanner that bypasses its own client and asks for a second grant on the wire.
        guard.sock.sendall(b'{{"op":"admit","kind":"http"}}\n')
        time.sleep(10)
    if host == "hang.example.test":
        guard.admit()
        time.sleep(30)
    if host == "nogate.example.test":
        finish()
except AdmissionRefused as exc:
    sys.stdout.write(json.dumps({{"ok": False, "error": "fixture_refused"}}) + "\n")
    raise SystemExit(2)
'''


class _FlipGate:
    """Supervisor-side gate double: admits a fixed budget and can be cancelled at any moment."""

    def __init__(self, budget=100):
        self.budget = budget
        self.cancelled = threading.Event()
        self.admits = 0
        self.probes = 0
        self.log = []

    def admit(self):
        self.log.append(("admit", time.monotonic()))
        if self.cancelled.is_set():
            raise AdmissionDenied("job_cancelled")
        if self.admits >= self.budget:
            raise AdmissionDenied("budget_exhausted")
        self.admits += 1
        return Grant(self.admits, 1.0, 10.0, self.budget - self.admits)

    def probe(self):
        self.probes += 1
        if self.cancelled.is_set():
            raise AdmissionDenied("job_cancelled")


@unittest.skipUnless(sys.platform.startswith("linux"), "the supervisor uses Linux process isolation APIs")
class SupervisorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        integrations = root / "integrations"
        worker = integrations / "worker"
        worker.mkdir(parents=True)
        (integrations / "__init__.py").write_text("", encoding="utf-8")
        (worker / "__init__.py").write_text("", encoding="utf-8")
        for name in ("admission.py", "network.py", "protocol.py"):
            (worker / name).symlink_to(REPO_ROOT / "integrations" / "worker" / name)
        self.root = root
        self.worker = worker
        patches = [
            mock.patch("integrations.worker.runner.os.geteuid", return_value=0),
            mock.patch("integrations.worker.runner._has_kill_capability", return_value=True),
            mock.patch("integrations.worker.runner._linux_preexec_limits", lambda: None),
            mock.patch.object(admission, "PROBE_INTERVAL_SECONDS", 0.05),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def runner_for(self, recorder):
        (self.worker / "scanner.py").write_text(
            _CHILD_SCRIPT.format(port=recorder.port, result=json.dumps(_result())), encoding="utf-8"
        )
        return SubprocessRunner(repo_root=str(self.root))

    def test_a_scan_without_a_gate_never_starts(self):
        with self.assertRaises(ScannerFailure) as refused:
            SubprocessRunner(repo_root=str(self.root)).run("https://three.example.test/", timeout=5)
        self.assertEqual(refused.exception.slug, "admission_guard_required")

    def test_every_request_is_admitted_and_the_scan_completes(self):
        recorder = _Recorder(self)
        gate = _FlipGate()
        result = self.runner_for(recorder).run("https://three.example.test/", timeout=10, gate=gate)
        self.assertEqual(result["status"], "no_evidence")
        self.assertEqual(gate.admits, 3)
        self.assertEqual([path for _t, path in recorder.requests], ["/r0", "/r1", "/r2"])

    def test_budget_exhaustion_stops_the_scan_at_the_boundary(self):
        recorder = _Recorder(self)
        gate = _FlipGate(budget=2)
        with self.assertRaises(ScannerFailure) as stopped:
            self.runner_for(recorder).run("https://three.example.test/", timeout=10, gate=gate)
        self.assertEqual(stopped.exception.slug, "admission_budget_exhausted")
        self.assertEqual([path for _t, path in recorder.requests], ["/r0", "/r1"])

    def test_cancellation_before_the_first_request_sends_nothing(self):
        recorder = _Recorder(self)
        gate = _FlipGate()
        gate.cancelled.set()
        with self.assertRaises(ScannerFailure) as stopped:
            self.runner_for(recorder).run("https://three.example.test/", timeout=10, gate=gate)
        self.assertEqual(stopped.exception.slug, "admission_job_cancelled")
        self.assertEqual(recorder.requests, [])

    def test_cancellation_during_an_in_flight_request_aborts_it_and_admits_nothing_further(self):
        recorder = _Recorder(self, delay=6.0)
        gate = _FlipGate()
        started = time.monotonic()
        cancelled_at = []

        def cancel_when_request_arrives():
            while not recorder.requests:
                time.sleep(0.01)
            cancelled_at.append(time.monotonic())
            gate.cancelled.set()

        thread = threading.Thread(target=cancel_when_request_arrives, daemon=True)
        thread.start()
        with self.assertRaises(ScannerFailure) as stopped:
            self.runner_for(recorder).run("https://slow.example.test/", timeout=20, gate=gate)
        thread.join(2)
        self.assertEqual(stopped.exception.slug, "admission_job_cancelled")
        self.assertEqual([path for _t, path in recorder.requests], ["/slow"], "only the already admitted request was sent")
        self.assertEqual(gate.admits, 1)
        self.assertLess(time.monotonic() - cancelled_at[0], 1.5, "the admitted request was not aborted promptly")
        self.assertLess(time.monotonic() - started, 5.0, "the supervisor waited for the slow response")

    def test_cancellation_during_backoff_between_requests_admits_nothing(self):
        recorder = _Recorder(self)
        gate = _FlipGate()

        def cancel_after_first():
            while not recorder.requests:
                time.sleep(0.01)
            time.sleep(0.3)  # the scanner is now idle in its backoff
            gate.cancelled.set()

        thread = threading.Thread(target=cancel_after_first, daemon=True)
        thread.start()
        with self.assertRaises(ScannerFailure) as stopped:
            self.runner_for(recorder).run("https://backoff.example.test/", timeout=10, gate=gate)
        thread.join(2)
        self.assertEqual(stopped.exception.slug, "admission_job_cancelled")
        self.assertEqual([path for _t, path in recorder.requests], ["/first"])

    def test_request_not_finished_within_the_disclosed_bound_is_killed(self):
        recorder = _Recorder(self)
        gate = _FlipGate()
        short = Grant(1, 1.0, 0.3, 5)
        gate.admit = lambda: (gate.log.append(("admit", time.monotonic())), short)[1]
        with mock.patch.object(admission, "REQUEST_GRACE_SECONDS", 0.1):
            with self.assertRaises(ScannerFailure) as stopped:
                self.runner_for(recorder).run("https://hang.example.test/", timeout=10, gate=gate)
        self.assertEqual(stopped.exception.slug, "request_deadline_exceeded")

    def test_a_scanner_that_breaks_the_protocol_is_killed(self):
        recorder = _Recorder(self)
        with self.assertRaises(ScannerFailure) as stopped:
            self.runner_for(recorder).run("https://double.example.test/", timeout=10, gate=_FlipGate())
        self.assertEqual(stopped.exception.slug, "admission_protocol_violation")

    def test_a_result_is_never_accepted_once_admission_was_refused(self):
        # The child finishes normally after a refusal it ignored; the supervisor still fails the run.
        recorder = _Recorder(self)
        gate = _FlipGate(budget=0)
        with self.assertRaises(ScannerFailure):
            self.runner_for(recorder).run("https://three.example.test/", timeout=10, gate=gate)


class ServiceWiringTests(unittest.TestCase):
    def test_the_worker_service_hands_the_gate_to_the_runner_and_reports_the_failure(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        spool = DurableSpool(Path(temp.name) / "spool")
        spool.prepare()
        api = _FakeAPI(_claim())

        class Runner:
            gate = None

            def run(self, target, *, timeout, stop_event=None, gate=None):
                Runner.gate = gate
                raise ScannerFailure("admission_job_cancelled")

        service = WorkerService(api, spool, Runner(), REVISION, clock=lambda: NOW)
        self.assertEqual(service.process_once(), "callback_accepted")
        self.assertIsInstance(Runner.gate, AdmissionGate)
        receipt = json.loads(api.result_bodies[0])
        self.assertEqual((receipt["outcome"], receipt["error"], receipt["result"]), ("failed", "admission_job_cancelled", None))


if __name__ == "__main__":
    unittest.main()
