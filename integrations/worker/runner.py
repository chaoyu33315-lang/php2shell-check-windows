"""Bounded root supervisor to unprivileged isolated scanner process."""

from __future__ import annotations

import json
import os
import platform
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

from wordpress_check import PHP2SHELL_CVES, PHP2SHELL_RULES_DATE, PHP2SHELL_SOURCES, Result, assess_php2shell

from .admission import AdmissionPump
from .network import RequestOrigin


MAX_SCANNER_STDOUT = 32 * 1024
MAX_SCANNER_STDERR = 4 * 1024
MAX_SCANNER_INPUT = 8192
MAX_WALL_SECONDS = 180
ALLOWED_RESULT_STATUSES = {"wordpress", "likely_wordpress", "no_evidence", "blocked", "error", "uncertain"}
ALLOWED_FETCH_STATUSES = {"ok", "blocked", "timeout", "dns_error"}
ALLOWED_PHP2SHELL_STATUSES = {"potentially_affected", "fixed_version_reported", "unknown"}
ALLOWED_VERSION_STATUSES = {
    "version_not_disclosed",
    "conflicting_versions",
    "unrecognized_or_partial_version",
    "branch_requires_vendor_review",
    "prerelease_unverified",
    "vendor_build_unverified",
    "below_upstream_fix",
    "at_or_above_upstream_fix",
}
SAFE_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ScannerFailure(Exception):
    def __init__(self, slug: str):
        super().__init__(slug)
        self.slug = slug


def _read_bounded(stream, limit: int, buffers: dict, key: str, overflow: threading.Event):
    while True:
        try:
            chunk = stream.read(8192)
        except (OSError, ValueError):
            return
        if not chunk:
            return
        current = buffers[key]
        remaining = limit + 1 - len(current)
        if remaining > 0:
            current.extend(chunk[:remaining])
        if len(chunk) > remaining or len(current) > limit:
            overflow.set()
            return


def _linux_preexec_limits():
    import resource

    # Fail closed before the child can execute Python if any isolation step fails.
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        os._exit(125)
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    os.umask(0o077)


def _has_kill_capability() -> bool:
    """A root supervisor must retain CAP_KILL to stop its unprivileged child."""
    if os.name != "posix" or not sys.platform.startswith("linux") or os.geteuid() != 0:
        return False
    try:
        with open("/proc/self/status", "r", encoding="ascii") as status:
            for line in status:
                if line.startswith("CapEff:"):
                    effective = int(line.split(":", 1)[1].strip(), 16)
                    return bool(effective & (1 << 5))  # Linux CAP_KILL
    except (OSError, ValueError):
        return False
    return False


def _close_pipes(process):
    for stream in (getattr(process, "stdin", None), getattr(process, "stdout", None), getattr(process, "stderr", None)):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


class SubprocessRunner:
    """Run exactly one normalized target with bounded IO, time, and privileges."""

    def __init__(self, *, repo_root=None, popen=subprocess.Popen, monotonic=time.monotonic):
        self.repo_root = os.path.abspath(repo_root or os.path.join(os.path.dirname(__file__), "..", ".."))
        self._popen = popen
        self._monotonic = monotonic

    def run(self, target: str, *, timeout: float = MAX_WALL_SECONDS, stop_event=None, gate=None, task=None) -> dict:
        # Fail closed by construction: without an admission gate there is no scan.
        if gate is None:
            raise ScannerFailure("admission_guard_required")
        if not sys.platform.startswith("linux") or os.name != "posix" or os.geteuid() != 0:
            raise ScannerFailure("scanner_isolation_unavailable")
        if not _has_kill_capability():
            raise ScannerFailure("scanner_kill_capability_unavailable")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= MAX_WALL_SECONDS:
            raise ScannerFailure("invalid_scanner_deadline")
        try:
            scope, normalized = RequestOrigin.from_target(target)
        except ValueError as exc:
            raise ScannerFailure("invalid_target") from exc
        if normalized != target:
            raise ScannerFailure("invalid_target")
        if task not in {None, "control_dns", "control_https"}:
            raise ScannerFailure("invalid_scanner_task")
        message = {"target": normalized} if task is None else {"target": normalized, "task": task}
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_SCANNER_INPUT:
            raise ScannerFailure("scanner_input_too_large")
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": self.repo_root,
        }
        try:
            parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as exc:
            raise ScannerFailure("admission_channel_unavailable") from exc
        child_fd = child_sock.fileno()
        env["CT_ADMISSION_FD"] = str(child_fd)
        command = [sys.executable, "-m", "integrations.worker.scanner"]
        try:
            process = self._popen(
                command,
                cwd=self.repo_root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(child_fd,),
                start_new_session=True,
                preexec_fn=_linux_preexec_limits,
                bufsize=0,
            )
        except (OSError, ValueError) as exc:
            parent_sock.close()
            child_sock.close()
            raise ScannerFailure("scanner_start_failed") from exc
        child_sock.close()
        pump = AdmissionPump(parent_sock, gate, kind="http" if task is None else "control")

        try:
            buffers = {"stdout": bytearray(), "stderr": bytearray()}
            overflow = threading.Event()
            stdout_reader = threading.Thread(
                target=_read_bounded,
                args=(process.stdout, MAX_SCANNER_STDOUT, buffers, "stdout", overflow),
                daemon=True,
            )
            stderr_reader = threading.Thread(
                target=_read_bounded,
                args=(process.stderr, MAX_SCANNER_STDERR, buffers, "stderr", overflow),
                daemon=True,
            )
            stdout_reader.start()
            stderr_reader.start()
            try:
                view = memoryview(payload)
                while view:
                    written = process.stdin.write(view)
                    if not written:
                        raise OSError("short scanner input write")
                    view = view[written:]
                process.stdin.close()
            except OSError:
                self._kill_process(process)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._kill_process(process)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired as exc:
                        _close_pipes(process)
                        raise ScannerFailure("scanner_termination_failed") from exc
                stdout_reader.join(timeout=2)
                stderr_reader.join(timeout=2)
                _close_pipes(process)
                raise ScannerFailure("scanner_input_failed")

            deadline = self._monotonic() + float(timeout)
            timed_out = False
            stopped = False
            while process.poll() is None:
                if overflow.is_set():
                    self._kill_process(process)
                    break
                if stop_event is not None and stop_event.is_set():
                    stopped = True
                    self._kill_process(process)
                    break
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._kill_process(process)
                    break
                fatal = None
                if pump.closed:
                    time.sleep(min(0.025, remaining))
                else:
                    readable, _, _ = select.select([parent_sock], [], [], min(0.025, remaining))
                    if readable:
                        fatal = pump.service()
                # Admission, cancellation, expiry and the in-flight bound are enforced here,
                # not by the scanner: any fatal reason kills it at once.
                fatal = fatal or pump.tick()
                if fatal:
                    self._kill_process(process)
                    break
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._kill_process(process)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired as exc:
                    _close_pipes(process)
                    raise ScannerFailure("scanner_termination_failed") from exc
            stdout_reader.join(timeout=2)
            stderr_reader.join(timeout=2)
            if stdout_reader.is_alive() or stderr_reader.is_alive():
                _close_pipes(process)
                stdout_reader.join(timeout=2)
                stderr_reader.join(timeout=2)
            else:
                _close_pipes(process)
            if timed_out:
                raise ScannerFailure("scanner_timeout")
            if stopped:
                raise ScannerFailure("worker_shutdown")
            if pump.fatal:
                raise ScannerFailure(pump.fatal)
            if overflow.is_set() or len(buffers["stdout"]) > MAX_SCANNER_STDOUT:
                raise ScannerFailure("scanner_output_overflow")
            if stdout_reader.is_alive() or stderr_reader.is_alive():
                raise ScannerFailure("scanner_pipe_stalled")
            if process.returncode != 0:
                child_error = self._parse_child_error(bytes(buffers["stdout"]))
                raise ScannerFailure(child_error or "scanner_process_failed")
            if task is not None:
                return self._parse_control_success(bytes(buffers["stdout"]), task)
            return self._parse_success(bytes(buffers["stdout"]), target, scope)
        finally:
            # Let an in-flight liveness probe finish before the socket and the API client are reused.
            pump.wait_probe(5.0)
            parent_sock.close()

    @staticmethod
    def _kill_process(process):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            try:
                process.kill()
            except OSError:
                pass

    @staticmethod
    def _parse_json_line(output: bytes):
        if not output or len(output) > MAX_SCANNER_STDOUT or not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise ScannerFailure("scanner_invalid_output")
        try:
            parsed = json.loads(output[:-1].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScannerFailure("scanner_invalid_output") from exc
        if not isinstance(parsed, dict):
            raise ScannerFailure("scanner_invalid_output")
        return parsed

    @classmethod
    def _parse_child_error(cls, output: bytes):
        try:
            parsed = cls._parse_json_line(output)
        except ScannerFailure:
            return None
        error = parsed.get("error")
        return error if parsed.get("ok") is False and isinstance(error, str) and SAFE_ERROR_RE.fullmatch(error) else None

    @classmethod
    def _parse_control_success(cls, output: bytes, task: str):
        parsed = cls._parse_json_line(output)
        if set(parsed) != {"ok", "control"} or parsed["ok"] is not True or not isinstance(parsed["control"], dict):
            raise ScannerFailure("scanner_invalid_output")
        control = parsed["control"]
        method = "dns_txt" if task == "control_dns" else "https_file"
        observed = control.get("observed")
        if (
            set(control) != {"method", "outcome", "observed"}
            or control["method"] != method
            or control["outcome"] not in {"observed", "not_found", "error"}
            or not isinstance(observed, list)
            or len(observed) > 8
            or any(not isinstance(item, str) for item in observed)
            or sum(len(item.encode("utf-8")) for item in observed) > 4096
            or (control["outcome"] != "observed" and observed)
        ):
            raise ScannerFailure("scanner_result_schema")
        return control

    @classmethod
    def _parse_success(cls, output: bytes, target: str, scope: RequestOrigin):
        parsed = cls._parse_json_line(output)
        if set(parsed) != {"ok", "result"} or type(parsed.get("ok")) is not bool or parsed["ok"] is not True:
            raise ScannerFailure("scanner_invalid_output")
        result = parsed["result"]
        cls.validate_result(result, target, scope)
        return result

    @staticmethod
    def validate_result(value, target: str, scope: RequestOrigin):
        if not isinstance(value, dict) or set(value) != set(Result.__dataclass_fields__):
            raise ScannerFailure("scanner_result_schema")
        for key in ("input_url", "final_url"):
            field_value = value[key]
            if not isinstance(field_value, str) or not field_value or len(field_value) > 4096:
                raise ScannerFailure("scanner_result_schema")
        if value["input_url"] != target:
            raise ScannerFailure("scanner_result_scope_mismatch")
        try:
            scope.validate_request(value["final_url"], mark_upgrade=False)
        except ValueError as exc:
            raise ScannerFailure("scanner_result_scope_mismatch") from exc
        if not isinstance(value["status"], str) or not isinstance(value["fetch_status"], str):
            raise ScannerFailure("scanner_result_status_invalid")
        if value["status"] not in ALLOWED_RESULT_STATUSES or value["fetch_status"] not in ALLOWED_FETCH_STATUSES:
            raise ScannerFailure("scanner_result_status_invalid")
        if not isinstance(value["php2shell_status"], str) or value["php2shell_status"] not in ALLOWED_PHP2SHELL_STATUSES:
            raise ScannerFailure("scanner_result_status_invalid")
        if not isinstance(value["php2shell_version_status"], str) or value["php2shell_version_status"] not in ALLOWED_VERSION_STATUSES:
            raise ScannerFailure("scanner_result_status_invalid")
        if value["php2shell_exploitability"] != "not_tested":
            raise ScannerFailure("scanner_result_status_invalid")
        if value["php2shell_rules_as_of"] != PHP2SHELL_RULES_DATE:
            raise ScannerFailure("scanner_revision_mismatch")
        if value["php2shell_cves"] != list(PHP2SHELL_CVES) or value["php2shell_sources"] != list(PHP2SHELL_SOURCES):
            raise ScannerFailure("scanner_result_schema")
        if value["http_status"] is not None and (
            isinstance(value["http_status"], bool)
            or not isinstance(value["http_status"], int)
            or not 100 <= value["http_status"] <= 599
        ):
            raise ScannerFailure("scanner_result_schema")
        status_code = value["http_status"]
        if value["fetch_status"] == "ok" and (status_code is None or not 200 <= status_code < 300):
            raise ScannerFailure("scanner_result_status_invalid")
        if value["status"] == "blocked" and value["fetch_status"] != "blocked":
            raise ScannerFailure("scanner_result_status_invalid")
        if value["fetch_status"] in {"dns_error", "timeout"}:
            if value["status"] != "error":
                raise ScannerFailure("scanner_result_status_invalid")
        string_limits = {
            "status": 32,
            "fetch_status": 32,
            "wordpress_version": 256,
            "php_version": 256,
            "server": 2048,
            "powered_by": 2048,
            "title": 500,
            "checked_at": 64,
            "php2shell_status": 32,
            "php2shell_version_status": 64,
            "php2shell_fixed_version": 32,
            "php2shell_exploitability": 32,
            "php2shell_rules_as_of": 32,
            "php2shell_recommendation": 2048,
        }
        for key, limit in string_limits.items():
            if not isinstance(value[key], str) or len(value[key]) > limit:
                raise ScannerFailure("scanner_result_schema")
        try:
            datetime.fromisoformat(value["checked_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise ScannerFailure("scanner_result_schema") from exc
        list_limits = {
            "evidence": (256, 1024),
            "asset_version_hints": (512, 512),
            "notes": (128, 2048),
            "php_version_candidates": (32, 256),
            "php_evidence": (64, 1024),
            "php2shell_notes": (64, 2048),
        }
        for key, (count_limit, item_limit) in list_limits.items():
            items = value[key]
            if not isinstance(items, list) or len(items) > count_limit:
                raise ScannerFailure("scanner_result_schema")
            if any(not isinstance(item, str) or len(item) > item_limit for item in items):
                raise ScannerFailure("scanner_result_schema")
        candidates = value["php_version_candidates"]
        if candidates != sorted(set(candidates)):
            raise ScannerFailure("scanner_result_schema")
        if value["php_version"] != (candidates[0] if len(candidates) == 1 else ""):
            raise ScannerFailure("scanner_result_schema")
        expected_assessment = assess_php2shell(
            value["php_version"],
            version_candidates=candidates or None,
            php_hint=bool(value["php_evidence"]) or value["status"] in {"wordpress", "likely_wordpress"},
        )
        for key, expected in expected_assessment.items():
            if value[key] != expected:
                raise ScannerFailure("scanner_result_assessment_mismatch")
        if value["fetch_status"] in {"dns_error", "timeout"} and value["php2shell_status"] != "unknown":
            raise ScannerFailure("scanner_result_status_invalid")
        try:
            serialized_size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ScannerFailure("scanner_result_schema") from exc
        if serialized_size > MAX_SCANNER_STDOUT - 64:
            raise ScannerFailure("scanner_output_overflow")
        return value
