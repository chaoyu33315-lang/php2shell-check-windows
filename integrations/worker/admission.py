"""Per-request admission guard.

The sandboxed scanner holds no worker key and no authorization state. Before
each connection to the customer's site it asks the root supervisor over a
private socket; the supervisor asks WordPress (signed ``admit`` route), which
atomically checks cancellation, expiry, lease and budget under the queue lock.

Fail-closed rules:

* No grant, no connection. Any error, timeout, malformed answer, protocol
  violation or unavailable store is a refusal.
* A grant is reserved and consumed in one step, is valid for at most
  ``MAX_VALID_SECONDS`` and covers exactly one connection and request.
* Every supervisor call to WordPress has a hard wall-clock budget; a call that
  overruns it is a refusal. Requests and replies on the scanner socket carry a
  sequence number, and any channel error poisons the channel, so a late reply
  can never be read as the answer to a later request.
* Only one grant may be outstanding. The supervisor kills the scanner if a
  request is not reported finished within ``MAX_REQUEST_SECONDS`` (plus a short
  grace), if the scanner skips the protocol, or if WordPress reports that the
  job is no longer live.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, replace

from .protocol import APIError


MAX_VALID_SECONDS = 1.0
MAX_REQUEST_SECONDS = 10.0
# No grace: a request must be finished within the disclosed ten seconds of the grant.
REQUEST_GRACE_SECONDS = 0.0
PROBE_INTERVAL_SECONDS = 2.0
MAX_ADMIT_WAIT_SECONDS = 4.0
CALL_BUDGET_SECONDS = 4.0
# A grant that took longer than this to come back is discarded and asked for again (the
# discarded slot stays spent): the child must still have most of its one second.
MAX_GRANT_AGE_SECONDS = 0.6
MAX_STALE_REGRANTS = 2
BUSY_RETRY_SECONDS = 0.15
MAX_MESSAGE_BYTES = 256
CHILD_REPLY_TIMEOUT_SECONDS = 15.0
REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
RETRYABLE_BUSY = {"queue_busy", "admission_write_failed"}
# Probe answers that say nothing about whether the job is live. They never abort a
# request already admitted (its own ten-second bound still applies) and the next
# admission fails closed on them. ``queue_busy`` only means the queue lock was held
# elsewhere (often by this supervisor's own concurrent admission); ``admission_error``
# means WordPress failed while deciding. Every explicit refusal stays fatal.
PROBE_INCONCLUSIVE = {"guard_unavailable", "guard_timeout", "admission_response_invalid", "queue_busy", "admission_error"}


class AdmissionDenied(Exception):
    """A refusal with a log-safe reason. Never converted into permission."""

    def __init__(self, slug: str, *, retry_after_ms: int = 0):
        super().__init__(slug)
        self.slug = slug if REASON_RE.fullmatch(slug or "") else "admission_denied"
        self.retry_after_ms = retry_after_ms


@dataclass(frozen=True)
class Grant:
    sequence: int
    valid_seconds: float
    timeout_seconds: float
    remaining: int
    # Supervisor monotonic time just before the call that WordPress granted: the
    # grant's one-second lifetime and ten-second bound are measured from here.
    issued_at: float = 0.0


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_grant(value) -> Grant:
    """Strictly validate a WordPress grant and clamp it to the disclosed hard bounds."""
    expected = {"ok", "admitted", "sequence", "valid_ms", "timeout_ms", "http_remaining"}
    if not isinstance(value, dict) or set(value) != expected or value["ok"] is not True or value["admitted"] is not True:
        raise AdmissionDenied("admission_response_invalid")
    sequence, valid_ms, timeout_ms, remaining = (value[k] for k in ("sequence", "valid_ms", "timeout_ms", "http_remaining"))
    if not all(_is_int(item) for item in (sequence, valid_ms, timeout_ms, remaining)):
        raise AdmissionDenied("admission_response_invalid")
    if sequence < 1 or valid_ms < 1 or timeout_ms < 1 or remaining < 0:
        raise AdmissionDenied("admission_response_invalid")
    return Grant(
        sequence,
        min(valid_ms / 1000.0, MAX_VALID_SECONDS),
        min(timeout_ms / 1000.0, MAX_REQUEST_SECONDS),
        remaining,
    )


def parse_refusal(error: APIError) -> AdmissionDenied:
    """Turn a non-2xx answer into a refusal; unknown or malformed answers stay refusals."""
    payload = getattr(error, "payload", None)
    if isinstance(payload, dict) and payload.get("error") == "ct_scan_disabled":
        # The operator kill switch (or an incomplete schema upgrade): not merely "unreachable".
        return AdmissionDenied("integration_disabled")
    reason = payload.get("reason") if isinstance(payload, dict) else None
    if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
        reason = "guard_unavailable"
    retry = payload.get("retry_after_ms") if isinstance(payload, dict) else 0
    if not _is_int(retry) or retry < 0:
        retry = 0
    return AdmissionDenied(reason, retry_after_ms=min(retry, 1000))


class AdmissionGate:
    """Supervisor-side client for the WordPress admission route."""

    def __init__(self, api, claim, *, kind="http", stop_event=None, deadline=None, clock=time.time, monotonic=time.monotonic):
        if kind not in {"http", "control"}:
            raise ValueError("invalid_admission_kind")
        self.api = api
        self.claim = claim
        self.kind = kind
        self.stop_event = stop_event
        # Wall-clock (epoch) time after which no further admission is requested at all.
        self.deadline = deadline
        self._clock = clock
        self._monotonic = monotonic

    def _wait(self, seconds: float):
        if self.stop_event is not None:
            if self.stop_event.wait(seconds):
                raise AdmissionDenied("worker_shutdown")
        else:
            time.sleep(seconds)

    def _check_local(self):
        if self.stop_event is not None and self.stop_event.is_set():
            raise AdmissionDenied("worker_shutdown")
        if self._clock() >= self.claim.expires_at.timestamp():
            raise AdmissionDenied("authorization_expired")
        if self.deadline is not None and self._clock() >= self.deadline:
            raise AdmissionDenied("scan_deadline")

    def _call(self, kind: str):
        """One WordPress call under a hard wall-clock budget (a slow store is a refusal)."""
        box = {}

        def run():
            try:
                box["value"] = self.api.admit(self.claim, kind)
            except BaseException as exc:  # reported to the caller as a refusal below
                box["error"] = exc

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        budget_end = self._monotonic() + CALL_BUDGET_SECONDS
        while worker.is_alive():
            # Sliced so shutdown interrupts a slow store; a late answer from an abandoned call is ignored.
            worker.join(0.05)
            if self.stop_event is not None and self.stop_event.is_set():
                raise AdmissionDenied("worker_shutdown")
            if worker.is_alive() and self._monotonic() >= budget_end:
                raise AdmissionDenied("guard_timeout")
        error = box.get("error")
        if isinstance(error, APIError):
            if error.status is None:
                raise AdmissionDenied("guard_unavailable") from error
            raise parse_refusal(error) from error
        if error is not None:
            raise AdmissionDenied("guard_unavailable") from error
        return box["value"]

    def admit(self) -> Grant:
        """Reserve exactly one request, or raise AdmissionDenied. Retries are bounded."""
        deadline = self._monotonic() + MAX_ADMIT_WAIT_SECONDS
        stale = 0
        while True:
            self._check_local()
            started = self._monotonic()
            try:
                grant = replace(parse_grant(self._call(self.kind)), issued_at=started)
                if self._monotonic() - started > MAX_GRANT_AGE_SECONDS:
                    # WordPress answered, but too slowly for the one-second lifetime to be useful.
                    stale += 1
                    if stale > MAX_STALE_REGRANTS or self._monotonic() >= deadline:
                        # Bounded by the same admission deadline as every other retry.
                        raise AdmissionDenied("admission_expired")
                    continue
                return grant
            except AdmissionDenied as denied:
                if self._monotonic() >= deadline:
                    raise
                if denied.slug == "rate_wait" and denied.retry_after_ms > 0:
                    self._wait(min(denied.retry_after_ms / 1000.0, 1.0))
                elif denied.slug in RETRYABLE_BUSY:
                    self._wait(BUSY_RETRY_SECONDS)
                else:
                    raise

    def probe(self):
        """Ask whether the job is still live. Consumes no budget and does not pace.

        A busy queue lock is retried briefly within one call budget; if it stays
        busy the probe reports ``queue_busy``, which the pump treats as inconclusive.
        """
        probe_kind = "probe" if self.kind == "http" else "control_probe"
        busy_until = self._monotonic() + CALL_BUDGET_SECONDS
        while True:
            self._check_local()
            try:
                response = self._call(probe_kind)
                break
            except AdmissionDenied as denied:
                if denied.slug != "queue_busy" or self._monotonic() + BUSY_RETRY_SECONDS >= busy_until:
                    raise
                self._wait(BUSY_RETRY_SECONDS)
        if not isinstance(response, dict) or set(response) != {"ok", "live"} or response["ok"] is not True or response["live"] is not True:
            raise AdmissionDenied("admission_response_invalid")


class AdmissionPump:
    """Supervisor side of the scanner socket: a one-grant-at-a-time state machine.

    ``service`` and ``tick`` return a fatal reason slug when the scanner must be
    killed, and ``None`` otherwise. After a fatal reason the pump answers nothing.

    Messages are single JSON lines: ``{"op":"admit","kind":"http","n":N}`` answered
    by ``{"ok":true,"n":N,"valid_ms":M}`` or ``{"ok":false,"n":N,"reason":R}``, and
    ``{"op":"done","n":N}``. ``N`` counts the scanner's admissions from 1 and must
    advance by exactly one.
    """

    def __init__(self, sock, gate, *, kind="http", monotonic=time.monotonic):
        if kind not in {"http", "control"}:
            raise ValueError("invalid_admission_kind")
        self.sock = sock
        self.gate = gate
        self.kind = kind
        self._monotonic = monotonic
        self._buffer = bytearray()
        self._inflight_until = None
        self._inflight_n = None
        self._last_n = 0
        self._last_probe = monotonic()
        self._probe_thread = None
        self._probe_result = None
        self.grants = 0
        self.fatal = None
        self.closed = False

    @property
    def inflight(self) -> bool:
        return self._inflight_until is not None

    def _send(self, value) -> bool:
        data = json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"
        try:
            self.sock.settimeout(2.0)
            self.sock.sendall(data)
            return True
        except OSError:
            return False

    def _fail(self, slug: str):
        slug = slug if slug.startswith(("admission_", "request_")) else "admission_" + slug
        self.fatal = slug[:64] if REASON_RE.fullmatch(slug[:64]) else "admission_denied"
        return self.fatal

    def _handle(self, line: bytes):
        try:
            message = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._fail("admission_protocol_violation")
        if not isinstance(message, dict) or not _is_int(message.get("n")):
            return self._fail("admission_protocol_violation")
        number = message["n"]
        if set(message) == {"op", "n"} and message["op"] == "done":
            if not self.inflight or number != self._inflight_n:
                return self._fail("admission_protocol_violation")
            self._inflight_until = None
            self._inflight_n = None
            return None
        if set(message) == {"op", "kind", "n"} and message["op"] == "admit" and message["kind"] == self.kind:
            if self.inflight or number != self._last_n + 1:
                # One connection at a time and strictly sequential requests.
                return self._fail("admission_protocol_violation")
            self._last_n = number
            try:
                grant = self.gate.admit()
            except AdmissionDenied as denied:
                self._send({"ok": False, "n": number, "reason": denied.slug})
                return self._fail(denied.slug)
            elapsed = self._monotonic() - grant.issued_at if grant.issued_at else 0.0
            valid = grant.valid_seconds - elapsed
            if valid < 0.05:
                # The grant outlived its lifetime while the supervisor waited on the guard.
                self._send({"ok": False, "n": number, "reason": "admission_expired"})
                return self._fail("admission_expired")
            # The disclosed bounds are measured from just before WordPress granted.
            started = grant.issued_at or self._monotonic()
            self._inflight_until = started + grant.timeout_seconds + REQUEST_GRACE_SECONDS
            self._inflight_n = number
            self.grants += 1
            if not self._send({"ok": True, "n": number, "valid_ms": int(valid * 1000)}):
                return self._fail("admission_channel_failed")
            return None
        return self._fail("admission_protocol_violation")

    def service(self):
        """Read and handle whatever the scanner has sent. Call when the socket is readable."""
        if self.fatal:
            return self.fatal
        try:
            self.sock.settimeout(0)
            chunk = self.sock.recv(MAX_MESSAGE_BYTES + 1)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            self.closed = True
            return None
        if not chunk:
            self.closed = True
            return None
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            line, _, rest = bytes(self._buffer).partition(b"\n")
            self._buffer = bytearray(rest)
            if len(line) > MAX_MESSAGE_BYTES:
                return self._fail("admission_protocol_violation")
            fatal = self._handle(line)
            if fatal:
                return fatal
        if len(self._buffer) > MAX_MESSAGE_BYTES:
            return self._fail("admission_protocol_violation")
        return None

    def _probe_worker(self):
        try:
            self.gate.probe()
            self._probe_result = None
        except AdmissionDenied as denied:
            self._probe_result = denied
        except BaseException:
            self._probe_result = AdmissionDenied("guard_unavailable")

    def wait_probe(self, timeout: float = 10.0):
        """Wait for an outstanding probe (tests, and orderly shutdown)."""
        thread = self._probe_thread
        if thread is not None:
            thread.join(timeout)

    def tick(self):
        """Enforce the in-flight bound and watch for cancellation, expiry or revocation.

        Probes run on their own thread so a slow store can never delay the in-flight
        deadline, a shutdown or the kill itself.
        """
        if self.fatal:
            return self.fatal
        now = self._monotonic()
        if self._inflight_until is not None and now > self._inflight_until:
            return self._fail("request_deadline_exceeded")
        thread = self._probe_thread
        if thread is not None and not thread.is_alive():
            self._probe_thread = None
            denied, self._probe_result = self._probe_result, None
            # An inconclusive probe (unreachable guard, busy queue lock, store error) does
            # not abort the request already admitted (its own ten-second bound applies),
            # and the next admission fails closed. An explicit refusal, including a
            # disabled integration, stops the scanner now.
            if denied is not None and denied.slug not in PROBE_INCONCLUSIVE:
                return self._fail(denied.slug)
            thread = None
        if self._probe_thread is None and now - self._last_probe >= PROBE_INTERVAL_SECONDS:
            self._last_probe = now
            self._probe_result = None
            self._probe_thread = threading.Thread(target=self._probe_worker, daemon=True)
            self._probe_thread.start()
        return None


class AdmissionRefused(Exception):
    """Raised inside the scanner when no admission was granted.

    Deliberately not an OSError: the checker must not swallow it into an ordinary
    fetch error, because a refused admission ends the run as a failure."""


class ChildAdmission:
    """Scanner-side client of the supervisor socket. Holds no key and no state of record."""

    def __init__(self, sock, *, kind="http", monotonic=time.monotonic):
        if kind not in {"http", "control"}:
            raise ValueError("invalid_admission_kind")
        self.sock = sock
        self.kind = kind
        self._monotonic = monotonic
        self._granted_at = None
        self._valid_seconds = 0.0
        self._outstanding = False
        self._n = 0
        self._dead = False

    def _poison(self, reason: str):
        """After any channel error no later byte may be read as an answer."""
        self._dead = True
        self._outstanding = False
        try:
            self.sock.close()
        except OSError:
            pass
        raise AdmissionRefused(reason)

    def _read_line(self) -> bytes:
        deadline = self._monotonic() + CHILD_REPLY_TIMEOUT_SECONDS
        data = bytearray()
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                self._poison("admission_timeout")
            try:
                self.sock.settimeout(remaining)
                chunk = self.sock.recv(1)
            except OSError:
                self._poison("admission_channel_failed")
            if not chunk:
                self._poison("admission_channel_closed")
            if chunk == b"\n":
                return bytes(data)
            data.extend(chunk)
            if len(data) > MAX_MESSAGE_BYTES:
                self._poison("admission_reply_invalid")

    def admit(self):
        if self._dead:
            raise AdmissionRefused("admission_channel_failed")
        if self._outstanding:
            raise AdmissionRefused("admission_outstanding")
        self._n += 1
        try:
            self.sock.settimeout(5.0)
            self.sock.sendall(json.dumps({"op": "admit", "kind": self.kind, "n": self._n}, separators=(",", ":")).encode("ascii") + b"\n")
        except OSError:
            self._poison("admission_channel_failed")
        try:
            reply = json.loads(self._read_line().decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._poison("admission_reply_invalid")
        if not isinstance(reply, dict) or reply.get("n") != self._n or not _is_int(reply.get("n")):
            self._poison("admission_reply_invalid")
        if reply.get("ok") is not True:
            reason = reply.get("reason")
            # A refusal is final for this scanner.
            self._dead = True
            raise AdmissionRefused(reason if isinstance(reason, str) and REASON_RE.fullmatch(reason) else "admission_denied")
        valid_ms = reply.get("valid_ms")
        if set(reply) != {"ok", "n", "valid_ms"} or not _is_int(valid_ms) or not 1 <= valid_ms <= int(MAX_VALID_SECONDS * 1000):
            self._poison("admission_reply_invalid")
        self._granted_at = self._monotonic()
        self._valid_seconds = valid_ms / 1000.0
        self._outstanding = True

    def ensure_fresh(self):
        """Call immediately before connecting: a stale grant is never used."""
        if self._dead or not self._outstanding or self._granted_at is None:
            raise AdmissionRefused("admission_missing")
        if self._monotonic() - self._granted_at >= self._valid_seconds:
            raise AdmissionRefused("admission_expired")

    def done(self):
        """Report the request finished (success or failure). Idempotent."""
        if not self._outstanding:
            return
        self._outstanding = False
        self._granted_at = None
        try:
            self.sock.settimeout(2.0)
            self.sock.sendall(json.dumps({"op": "done", "n": self._n}, separators=(",", ":")).encode("ascii") + b"\n")
        except OSError:
            self._dead = True
