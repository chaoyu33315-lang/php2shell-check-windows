"""Private durable callback spool, expiry markers, heartbeat, and process lock."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import stat
import time
from pathlib import Path

from .protocol import API_MAX_BODY, JobClaim


MAX_SPOOL_FILE_BYTES = 128 * 1024
MAX_QUARANTINE_RECEIPTS = 100
QUARANTINE_TTL_SECONDS = 365 * 24 * 60 * 60
SAFE_FILENAME_RE = re.compile(r"(?:job|uncertain|receipt)-[0-9]{1,19}-lease-[0-9a-f]{24}\.json\Z")
TEMP_FILENAME_RE = re.compile(r"\.tmp-[0-9]+-[0-9a-f]{16}\Z")
SAFE_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class SpoolError(Exception):
    pass


class LockBusy(Exception):
    pass


def _lease_hash(lease: str) -> str:
    return hashlib.sha256(lease.encode("utf-8")).hexdigest()[:24]


class DurableSpool:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.pending = self.root / "pending"
        self.uncertain = self.root / "uncertain"
        self.quarantine = self.root / "quarantine"

    def prepare(self):
        self._ensure_directory(self.root)
        self._ensure_directory(self.pending)
        self._ensure_directory(self.uncertain)
        self._ensure_directory(self.quarantine)

    def cleanup_temps(self):
        """Remove only this process's generated atomic-write leftovers, under the lock."""
        for directory in (self.pending, self.uncertain, self.quarantine, self.root):
            try:
                entries = list(directory.iterdir())
            except OSError as exc:
                raise SpoolError("spool_read_failed") from exc
            for path in entries:
                if not TEMP_FILENAME_RE.fullmatch(path.name):
                    continue
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        raise SpoolError("spool_path_invalid")
                    if os.name == "posix" and (
                        info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
                    ):
                        raise SpoolError("spool_permissions_invalid")
                    path.unlink()
                    self._fsync_directory(directory)
                except SpoolError:
                    raise
                except OSError as exc:
                    raise SpoolError("spool_cleanup_failed") from exc

    @staticmethod
    def _ensure_directory(path: Path):
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=True)
            info = path.lstat()
        except OSError as exc:
            raise SpoolError("spool_unavailable") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SpoolError("spool_path_invalid")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise SpoolError("spool_permissions_invalid")
        try:
            os.chmod(path, 0o700)
        except OSError as exc:
            raise SpoolError("spool_permissions_invalid") from exc

    def _atomic_write(self, path: Path, raw: bytes):
        if len(raw) > MAX_SPOOL_FILE_BYTES:
            raise SpoolError("spool_record_too_large")
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise SpoolError("spool_unavailable") from exc
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)):
            raise SpoolError("spool_path_invalid")
        if path.parent not in {self.root, self.pending, self.uncertain, self.quarantine}:
            raise SpoolError("spool_path_invalid")
        temp = path.parent / f".tmp-{os.getpid()}-{os.urandom(8).hex()}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temp, flags, 0o600)
            try:
                view = memoryview(raw)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("short spool write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temp, path)
            self._fsync_directory(path.parent)
        except OSError as exc:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise SpoolError("spool_write_failed") from exc

    @staticmethod
    def _fsync_directory(path: Path):
        if os.name != "posix":
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read_file(self, path: Path, limit=MAX_SPOOL_FILE_BYTES) -> bytes:
        if not SAFE_FILENAME_RE.fullmatch(path.name):
            raise SpoolError("spool_filename_invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                    raise SpoolError("spool_record_invalid")
                if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
                    raise SpoolError("spool_permissions_invalid")
                chunks = []
                size = 0
                while True:
                    chunk = os.read(descriptor, 8192)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise SpoolError("spool_record_too_large")
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(descriptor)
        except SpoolError:
            raise
        except OSError as exc:
            raise SpoolError("spool_read_failed") from exc

    @staticmethod
    def _encode(value) -> bytes:
        try:
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise SpoolError("spool_record_invalid") from exc

    def write_heartbeat(self, epoch: int):
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch <= 0:
            raise SpoolError("heartbeat_invalid")
        self._atomic_write(self.root / "heartbeat.json", self._encode({"last_poll_epoch": epoch}))

    @property
    def heartbeat_path(self):
        return self.root / "heartbeat.json"

    def save_callback(self, claim: JobClaim, body: bytes):
        if not isinstance(body, bytes) or len(body) > API_MAX_BODY:
            raise SpoolError("callback_payload_invalid")
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpoolError("callback_payload_invalid") from exc
        if (
            not isinstance(data, dict)
            or isinstance(data.get("id"), bool)
            or data.get("id") != claim.job_id
            or data.get("lease") != claim.lease
        ):
            raise SpoolError("callback_binding_mismatch")
        stem = f"job-{claim.job_id}-lease-{_lease_hash(claim.lease)}"
        record = {
            "kind": "callback",
            "id": claim.job_id,
            "lease_hash": _lease_hash(claim.lease),
            "expires_at": int(claim.expires_at.timestamp()),
            "lease_until": int(claim.lease_until.timestamp()),
            "body": body.decode("utf-8"),
        }
        path = self.pending / f"{stem}.json"
        try:
            old = self._read_file(path)
        except FileNotFoundError:
            old = None
        except SpoolError as exc:
            if not path.exists():
                old = None
            else:
                raise exc
        encoded = self._encode(record)
        if old is not None:
            if old != encoded:
                raise SpoolError("callback_receipt_conflict")
            return path
        self._atomic_write(path, encoded)
        return path

    def save_start_uncertain(self, claim: JobClaim):
        lease_hash = _lease_hash(claim.lease)
        stem = f"uncertain-{claim.job_id}-lease-{lease_hash}"
        record = {
            "kind": "start_uncertain",
            "id": claim.job_id,
            "lease_hash": lease_hash,
            "expires_at": int(claim.expires_at.timestamp()),
            "lease_until": int(claim.lease_until.timestamp()),
        }
        path = self.uncertain / f"{stem}.json"
        self._atomic_write(path, self._encode(record))
        return path

    def save_running(self, claim: JobClaim, checker_revision: str, started_at: int):
        lease_hash = _lease_hash(claim.lease)
        stem = f"uncertain-{claim.job_id}-lease-{lease_hash}"
        record = {
            "kind": "running",
            "id": claim.job_id,
            "lease_hash": lease_hash,
            "lease": claim.lease,
            "scope_hash": claim.scope_hash,
            "expires_at": int(claim.expires_at.timestamp()),
            "lease_until": int(claim.lease_until.timestamp()),
            "started_at": started_at,
            "checker_revision": checker_revision,
        }
        path = self.uncertain / f"{stem}.json"
        self._atomic_write(path, self._encode(record))
        return path

    def callback_records(self):
        records = []
        try:
            paths = sorted(self.pending.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise SpoolError("spool_read_failed") from exc
        for path in paths:
            raw = self._read_file(path)
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SpoolError("spool_record_invalid") from exc
            if not self._valid_callback_record(record, path):
                raise SpoolError("spool_record_invalid")
            records.append((path, record))
        return records

    @staticmethod
    def _valid_callback_record(record, path):
        required = {"kind", "id", "lease_hash", "expires_at", "lease_until", "body"}
        if not isinstance(record, dict) or set(record) != required or record.get("kind") != "callback":
            return False
        if isinstance(record["id"], bool) or not isinstance(record["id"], int) or record["id"] < 1:
            return False
        if not isinstance(record["lease_hash"], str) or not re.fullmatch(r"[0-9a-f]{24}", record["lease_hash"]):
            return False
        if any(isinstance(record[key], bool) or not isinstance(record[key], int) for key in ("expires_at", "lease_until")):
            return False
        if not isinstance(record["body"], str) or len(record["body"].encode("utf-8")) > API_MAX_BODY:
            return False
        try:
            payload = json.loads(record["body"])
        except (UnicodeError, json.JSONDecodeError):
            return False
        if not isinstance(payload, dict) or payload.get("id") != record["id"]:
            return False
        lease = payload.get("lease")
        return (
            isinstance(lease, str)
            and _lease_hash(lease) == record["lease_hash"]
            and path.name == f"job-{record['id']}-lease-{record['lease_hash']}.json"
        )

    def remove_callback(self, path: Path):
        self._remove_generated(path, self.pending)

    def active_uncertain(self, now: int):
        active = []
        try:
            paths = sorted(self.uncertain.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise SpoolError("spool_read_failed") from exc
        for path in paths:
            raw = self._read_file(path)
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SpoolError("spool_record_invalid") from exc
            if not self._valid_uncertain_record(record, path):
                raise SpoolError("spool_record_invalid")
            if record["kind"] == "running":
                if now < record["started_at"] + 180:
                    active.append(record)
                elif record["expires_at"] > now:
                    active.append({**record, "recovery_due": True})
                else:
                    self._quarantine(record["id"], record["lease_hash"], "authorization_expired", b"", now)
                    self._remove_generated(path, self.uncertain)
            elif now < min(record["lease_until"], record["expires_at"]):
                active.append(record)
            else:
                self._quarantine(record["id"], record["lease_hash"], "start_ack_uncertain_expired", b"", now)
                self._remove_generated(path, self.uncertain)
        return active

    @staticmethod
    def _valid_uncertain_record(record, path):
        if not isinstance(record, dict):
            return False
        kind = record.get("kind")
        required = {"kind", "id", "lease_hash", "expires_at", "lease_until"}
        if kind == "running":
            required |= {"lease", "scope_hash", "started_at", "checker_revision"}
        elif kind != "start_uncertain":
            return False
        if set(record) != required:
            return False
        if isinstance(record["id"], bool) or not isinstance(record["id"], int) or record["id"] < 1:
            return False
        if not isinstance(record["lease_hash"], str) or not re.fullmatch(r"[0-9a-f]{24}", record["lease_hash"]):
            return False
        time_fields = ["expires_at", "lease_until"]
        if kind == "running":
            time_fields.append("started_at")
            if (
                not isinstance(record["lease"], str)
                or _lease_hash(record["lease"]) != record["lease_hash"]
                or not isinstance(record["scope_hash"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["scope_hash"])
                or not isinstance(record["checker_revision"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", record["checker_revision"])
            ):
                return False
        if any(isinstance(record[key], bool) or not isinstance(record[key], int) for key in time_fields):
            return False
        return path.name == f"uncertain-{record['id']}-lease-{record['lease_hash']}.json"

    def quarantine_callback(self, path: Path, record: dict, reason: str, now: int):
        if not SAFE_ERROR_RE.fullmatch(reason):
            raise SpoolError("quarantine_reason_invalid")
        body = record["body"].encode("utf-8")
        self._quarantine(record["id"], record["lease_hash"], reason, body, now)
        self.remove_callback(path)

    def remove_uncertain(self, job_id: int, lease_hash: str):
        path = self.uncertain / f"uncertain-{job_id}-lease-{lease_hash}.json"
        self._remove_generated(path, self.uncertain)

    def quarantine_marker(self, record: dict, reason: str, now: int):
        if not SAFE_ERROR_RE.fullmatch(reason):
            raise SpoolError("quarantine_reason_invalid")
        self._quarantine(record["id"], record["lease_hash"], reason, b"", now)
        self.remove_uncertain(record["id"], record["lease_hash"])

    def _quarantine(self, job_id: int, lease_hash: str, reason: str, body: bytes, now: int):
        record = {
            "id": job_id,
            "lease_hash": lease_hash,
            "reason": reason,
            "payload_sha256": hashlib.sha256(body).hexdigest(),
            "payload_b64": base64.b64encode(body).decode("ascii"),
            "quarantined_at": now,
        }
        path = self.quarantine / f"receipt-{job_id}-lease-{lease_hash}.json"
        self._atomic_write(path, self._encode(record))
        self.prune_quarantine(now)

    def prune_quarantine(self, now: int):
        """Enforce receipt TTL/count bounds during ordinary idle polling too."""
        if isinstance(now, bool) or not isinstance(now, int) or now <= 0:
            raise SpoolError("quarantine_time_invalid")
        try:
            receipts = list(self.quarantine.iterdir())
        except OSError as exc:
            raise SpoolError("quarantine_prune_failed") from exc
        for old in receipts:
            try:
                raw_old = self._read_file(old)
                old_record = json.loads(raw_old.decode("utf-8"))
            except (SpoolError, UnicodeDecodeError, json.JSONDecodeError):
                raise SpoolError("quarantine_record_invalid")
            if (
                not isinstance(old_record, dict)
                or isinstance(old_record.get("quarantined_at"), bool)
                or not isinstance(old_record.get("quarantined_at"), int)
            ):
                raise SpoolError("quarantine_record_invalid")
            if old_record["quarantined_at"] < now - QUARANTINE_TTL_SECONDS:
                self._remove_generated(old, self.quarantine)
        try:
            receipts = sorted(self.quarantine.iterdir(), key=lambda item: item.stat().st_mtime_ns)
        except OSError as exc:
            raise SpoolError("quarantine_prune_failed") from exc
        for old in receipts[:-MAX_QUARANTINE_RECEIPTS]:
            self._remove_generated(old, self.quarantine)

    @staticmethod
    def _remove_generated(path: Path, parent: Path):
        if path.parent != parent or not SAFE_FILENAME_RE.fullmatch(path.name):
            raise SpoolError("spool_path_invalid")
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise SpoolError("spool_path_invalid")
            path.unlink()
            DurableSpool._fsync_directory(parent)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SpoolError("spool_remove_failed") from exc


class ProcessLock:
    def __init__(self, spool: DurableSpool):
        self.spool = spool
        self._file = None

    def acquire(self):
        if os.name != "posix":
            raise SpoolError("worker_lock_unavailable")
        try:
            import fcntl
        except ImportError as exc:
            raise SpoolError("worker_lock_unavailable") from exc
        path = self.spool.root / "worker.lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                os.close(descriptor)
                raise SpoolError("worker_lock_invalid")
            if info.st_uid != os.geteuid():
                os.close(descriptor)
                raise SpoolError("worker_lock_invalid")
            self._file = os.fdopen(descriptor, "r+")
            try:
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                self._file.close()
                self._file = None
                raise LockBusy("worker_already_running") from exc
        except SpoolError:
            raise
        except OSError as exc:
            raise SpoolError("worker_lock_unavailable") from exc
        return self

    def release(self):
        if self._file is None:
            return
        try:
            import fcntl

            fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *_exc):
        self.release()
