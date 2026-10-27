"""Authenticated polling supervisor for the authorized PHP2Shell worker."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .admission import AdmissionGate
from .network import RequestOrigin
from .protocol import (
    APIClient,
    APIError,
    API_MAX_BODY,
    API_SITE_URL,
    JobClaim,
    MAX_LEASE_SECONDS,
)
from .runner import MAX_WALL_SECONDS, ScannerFailure, SubprocessRunner, _has_kill_capability
from .spool import DurableSpool, LockBusy, ProcessLock, SpoolError


REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
POLL_INTERVAL_DEFAULT = 15
MAX_POLL_INTERVAL = 300
CALLBACK_RESERVE_SECONDS = 5
CALLBACK_LEASE_GRACE_SECONDS = 60 * 60
PERMANENT_CALLBACK_STATUSES = {400, 413, 422}
CONTACT = "https://complete.tech/services/website-security/"


class WorkerConfigError(Exception):
    def __init__(self, slug: str):
        super().__init__(slug)
        self.slug = slug


@dataclass(frozen=True)
class WorkerConfig:
    api_site_url: str
    secret_file: Path
    spool_root: Path
    checker_revision: str
    poll_seconds: int


def load_config(env=None) -> WorkerConfig:
    env = os.environ if env is None else env
    api_site_url = env.get("CT_SCAN_SITE_URL", API_SITE_URL)
    try:
        parts = urlsplit(api_site_url)
        port = parts.port
    except (AttributeError, TypeError, ValueError) as exc:
        raise WorkerConfigError("invalid_site_url") from exc
    if (
        parts.scheme.lower() != "https"
        or parts.hostname != "complete.tech"
        or parts.username is not None
        or parts.password is not None
        or port not in {None, 443}
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise WorkerConfigError("invalid_site_url")
    api_site_url = "https://complete.tech"
    secret_file = Path(env.get("CT_SCAN_SECRET_FILE", ""))
    if not str(secret_file) or not secret_file.is_absolute():
        raise WorkerConfigError("invalid_secret_file")
    spool_root = Path(env.get("CT_SCAN_SPOOL", "/var/lib/ct-scan"))
    if not spool_root.is_absolute():
        raise WorkerConfigError("invalid_spool_path")
    revision = env.get("CT_SCAN_REVISION", "")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise WorkerConfigError("invalid_checker_revision")
    try:
        poll_seconds = int(env.get("CT_SCAN_POLL_SECONDS", str(POLL_INTERVAL_DEFAULT)))
    except (TypeError, ValueError) as exc:
        raise WorkerConfigError("invalid_poll_interval") from exc
    if not 1 <= poll_seconds <= MAX_POLL_INTERVAL:
        raise WorkerConfigError("invalid_poll_interval")
    return WorkerConfig(api_site_url, secret_file, spool_root, revision, poll_seconds)


def load_secret(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise WorkerConfigError("secret_file_invalid")
            if os.name == "posix":
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                    raise WorkerConfigError("secret_permissions_invalid")
            raw = os.read(descriptor, 513)
            if len(raw) > 512:
                raise WorkerConfigError("secret_file_invalid")
        finally:
            os.close(descriptor)
    except WorkerConfigError:
        raise
    except OSError as exc:
        raise WorkerConfigError("secret_file_unavailable") from exc
    raw = raw.rstrip(b"\r\n")
    if not 32 <= len(raw) <= 512 or any(byte < 33 or byte > 126 for byte in raw):
        raise WorkerConfigError("secret_file_invalid")
    return raw


def _lease_hash(lease: str) -> str:
    return hashlib.sha256(lease.encode("utf-8")).hexdigest()[:24]


class WorkerService:
    def __init__(self, api: APIClient, spool: DurableSpool, runner, checker_revision: str, *, clock=time.time):
        if not REVISION_RE.fullmatch(checker_revision):
            raise WorkerConfigError("invalid_checker_revision")
        self.api = api
        self.spool = spool
        self.runner = runner
        self.checker_revision = checker_revision
        self.clock = clock
        self.stop_event = threading.Event()

    def _callback_body(self, job_id, lease, scope_hash, outcome, result, error, revision=None) -> bytes:
        if outcome not in {"completed", "failed"}:
            raise SpoolError("callback_payload_invalid")
        if outcome == "completed":
            if result is None or error != "":
                raise SpoolError("callback_payload_invalid")
        else:
            if result is not None or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error or ""):
                raise SpoolError("callback_payload_invalid")
        payload = {
            "id": job_id,
            "lease": lease,
            "scope_hash": scope_hash,
            "outcome": outcome,
            "result": result,
            "error": error,
            "checker_revision": revision or self.checker_revision,
        }
        try:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise SpoolError("callback_payload_invalid") from exc
        if len(body) > API_MAX_BODY:
            raise SpoolError("callback_payload_too_large")
        return body

    def _flush_one(self, path, record, now: int):
        retry_deadline = min(
            record["expires_at"], record["lease_until"] + CALLBACK_LEASE_GRACE_SECONDS
        )
        if now >= retry_deadline:
            reason = "authorization_expired" if now >= record["expires_at"] else "callback_retry_window_expired"
            self.spool.quarantine_callback(path, record, reason, now)
            return "callback_quarantined"
        try:
            response = self.api.result(record["body"].encode("utf-8"))
        except APIError as exc:
            if exc.status in ({409, 410} | PERMANENT_CALLBACK_STATUSES):
                self.spool.quarantine_callback(path, record, f"api_http_{exc.status}", now)
                return "callback_quarantined"
            return f"callback_pending_{exc.slug}"
        if type(response.get("ok")) is not bool or response["ok"] is not True:
            return "callback_pending_unacknowledged"
        self.spool.remove_callback(path)
        self.spool.remove_uncertain(record["id"], record["lease_hash"])
        return "callback_accepted"

    def _recover_running(self, record, now: int):
        if now >= record["expires_at"]:
            self.spool.quarantine_marker(record, "authorization_expired", now)
            return "running_quarantined"
        claim = JobClaim(
            record["id"],
            "",
            record["scope_hash"],
            "",
            datetime.fromtimestamp(record["expires_at"], timezone.utc),
            record["lease"],
            datetime.fromtimestamp(record["lease_until"], timezone.utc),
        )
        body = self._callback_body(
            claim.job_id,
            claim.lease,
            claim.scope_hash,
            "failed",
            None,
            "scanner_interrupted",
            revision=record["checker_revision"],
        )
        self.spool.save_callback(claim, body)
        self.spool.remove_uncertain(claim.job_id, _lease_hash(claim.lease))
        callbacks = self.spool.callback_records()
        if callbacks:
            path, receipt = callbacks[0]
            return self._flush_one(path, receipt, now)
        return "running_recovered"

    def process_once(self):
        now = int(self.clock())
        self.spool.prune_quarantine(now)
        callbacks = self.spool.callback_records()
        if callbacks:
            path, record = callbacks[0]
            self.spool.remove_uncertain(record["id"], record["lease_hash"])
            return self._flush_one(path, record, now)

        markers = self.spool.active_uncertain(now)
        if markers:
            if markers[0].get("recovery_due"):
                return self._recover_running(markers[0], now)
            return "waiting_for_lease"

        try:
            claim = self.api.claim()
        except APIError as exc:
            return f"claim_failed_{exc.slug}"
        self.spool.write_heartbeat(now)
        if claim is None:
            return self._process_control()

        try:
            scope, normalized = RequestOrigin.from_target(claim.target)
        except ValueError:
            return "claim_rejected_target"
        if normalized != claim.target or hashlib.sha256(claim.target.encode("utf-8")).hexdigest() != claim.scope_hash:
            return "claim_rejected_binding"
        # Persist this state before the network request. If its acknowledgement is
        # lost or the supervisor crashes, this lease is never started twice locally.
        self.spool.save_start_uncertain(claim)
        try:
            started = self.api.start(claim)
        except APIError:
            return "start_uncertain"
        if started is not True:
            return "start_uncertain"

        started_at = int(self.clock())
        self.spool.save_running(claim, self.checker_revision, started_at)
        remaining = min(claim.expires_at.timestamp(), claim.lease_until.timestamp()) - self.clock()
        scan_timeout = min(float(MAX_WALL_SECONDS), remaining - CALLBACK_RESERVE_SECONDS)
        if scan_timeout <= 0:
            outcome, result, error = "failed", None, "stale_claim"
        else:
            try:
                gate = AdmissionGate(self.api, claim, stop_event=self.stop_event, deadline=self.clock() + scan_timeout, clock=self.clock)
                result = self.runner.run(claim.target, timeout=scan_timeout, stop_event=self.stop_event, gate=gate)
                SubprocessRunner.validate_result(result, claim.target, scope)
                outcome, error = "completed", ""
            except ScannerFailure as exc:
                outcome, result, error = "failed", None, exc.slug
            except (TypeError, ValueError, KeyError):
                outcome, result, error = "failed", None, "scanner_result_invalid"

        body = self._callback_body(claim.job_id, claim.lease, claim.scope_hash, outcome, result, error)
        self.spool.save_callback(claim, body)
        self.spool.remove_uncertain(claim.job_id, _lease_hash(claim.lease))
        callbacks = self.spool.callback_records()
        if callbacks:
            return self._flush_one(*callbacks[0], int(self.clock()))
        return "callback_spooled"

    def _process_control(self):
        """Run at most one customer-requested target-control check (one query), if one is due."""
        try:
            task = self.api.control_claim()
        except APIError as exc:
            return f"control_claim_failed_{exc.slug}"
        if task is None:
            return "idle"
        try:
            RequestOrigin.from_target(task.target)
        except ValueError:
            return "control_rejected_target"
        remaining = min(task.expires_at.timestamp(), task.lease_until.timestamp()) - self.clock()
        timeout = min(30.0, remaining - CALLBACK_RESERVE_SECONDS)
        if timeout <= 0:
            return "control_stale"
        gate = AdmissionGate(self.api, task, kind="control", stop_event=self.stop_event, deadline=self.clock() + timeout, clock=self.clock)
        runner_task = "control_dns" if task.method == "dns_txt" else "control_https"
        try:
            control = self.runner.run(task.target, timeout=timeout, stop_event=self.stop_event, gate=gate, task=runner_task)
            outcome, observed = control["outcome"], control["observed"]
        except ScannerFailure as exc:
            if exc.slug.startswith("admission_"):
                # Refused or cancelled: nothing was checked. WordPress releases the lease; no result is posted.
                return f"control_{exc.slug}"
            outcome, observed = "error", []
        except (TypeError, ValueError, KeyError):
            outcome, observed = "error", []
        try:
            self.api.control_result(task, outcome, observed)
        except APIError as exc:
            # The attempt was already spent at admission; there is no retry and no rescan.
            return f"control_result_failed_{exc.slug}"
        return f"control_{outcome}"

    def run_forever(self, poll_seconds: int):
        while not self.stop_event.is_set():
            try:
                event = self.process_once()
            except SpoolError:
                self._log("spool_error")
                self.stop_event.set()
                break
            except BaseException:
                self._log("worker_iteration_failed")
                self.stop_event.set()
                break
            self._log(event)
            self.stop_event.wait(poll_seconds)

    @staticmethod
    def _log(event: str):
        safe_event = event if re.fullmatch(r"[a-z0-9_]{1,96}", event or "") else "worker_event"
        sys.stderr.write(f"worker {safe_event}\n")
        sys.stderr.flush()


def _service_main():
    if not sys.platform.startswith("linux") or os.name != "posix" or os.geteuid() != 0:
        sys.stderr.write("worker scanner_isolation_unavailable\n")
        return 2
    if not _has_kill_capability():
        sys.stderr.write("worker scanner_kill_capability_unavailable\n")
        return 2
    try:
        config = load_config()
        secret = load_secret(config.secret_file)
        spool = DurableSpool(config.spool_root)
        spool.prepare()
        lock = ProcessLock(spool)
        lock.acquire()
    except WorkerConfigError as exc:
        sys.stderr.write(f"worker {exc.slug}\n")
        return 2
    except (SpoolError, LockBusy) as exc:
        slug = "worker_already_running" if isinstance(exc, LockBusy) else "worker_startup_failed"
        sys.stderr.write(f"worker {slug}\n")
        return 2

    stop_event = threading.Event()
    service = WorkerService(APIClient(secret), spool, SubprocessRunner(), config.checker_revision)
    service.stop_event = stop_event
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _signum, _frame: stop_event.set())
    try:
        spool.cleanup_temps()
        service.run_forever(config.poll_seconds)
    finally:
        lock.release()
    return 0


def main():
    try:
        return _service_main()
    except BaseException:
        # Only safe categories are emitted; URL, target, secret, and exception text
        # never enter container logs.
        sys.stderr.write("worker fatal_error\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
