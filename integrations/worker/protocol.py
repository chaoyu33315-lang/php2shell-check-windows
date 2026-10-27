"""Authenticated HTTPS API client and strict claim/result wire validation."""

from __future__ import annotations

import http.client
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request

from .network import PinnedOpener, RequestOrigin


API_SITE_URL = "https://complete.tech"
API_HOST = "complete.tech"
API_BASE_PATH = "/wp-json/ct-scan/v1"
AUTH_ROUTE_PREFIX = "/ct-scan/v1"
ROUTES = frozenset(
    f"{AUTH_ROUTE_PREFIX}/{name}" for name in ("claim", "start", "admit", "result", "control/claim", "control/result")
)
CONTROL_METHODS = frozenset({"dns_txt", "https_file"})
CONTROL_OUTCOMES = frozenset({"observed", "not_found", "error"})
API_MAX_BODY = 64 * 1024
API_MAX_RESPONSE = 16 * 1024
MAX_JOB_ID = 2**63 - 1
MAX_LEASE_SECONDS = 15 * 60
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
LEASE_RE = re.compile(r"[A-Za-z0-9._~-]{16,512}\Z")
JOB_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class APIError(Exception):
    """A transport or protocol failure with a log-safe category."""

    def __init__(self, slug: str, *, status: int | None = None, payload=None):
        super().__init__(slug)
        self.slug = slug
        self.status = status
        # Parsed JSON object of a non-2xx answer, when one was returned (never logged).
        self.payload = payload


@dataclass(frozen=True)
class JobClaim:
    job_id: int
    target: str
    scope_hash: str
    terms_hash: str
    expires_at: datetime
    lease: str
    lease_until: datetime


@dataclass(frozen=True)
class ControlTask:
    """One customer-requested target-control check: a single TXT lookup or HTTPS request."""

    job_id: int
    target: str
    scope_hash: str
    method: str
    expires_at: datetime
    lease: str
    lease_until: datetime


def auth_headers(secret: bytes, timestamp: int, nonce: str, route: str, raw_body: bytes) -> dict[str, str]:
    if route not in ROUTES:
        raise ValueError("invalid_route")
    timestamp_text = str(timestamp)
    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"{timestamp_text}\n{nonce}\nPOST\n{route}\n{body_hash}".encode("ascii")
    signature = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-CT-Timestamp": timestamp_text,
        "X-CT-Nonce": nonce,
        "X-CT-Signature": signature,
    }


def _parse_iso8601(value, field_name: str) -> datetime:
    if isinstance(value, bool) or not isinstance(value, int):
        raise APIError(f"invalid_{field_name}")
    try:
        parsed = datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise APIError(f"invalid_{field_name}") from exc
    return parsed


def validate_claim(value, *, now: datetime | None = None) -> JobClaim | None:
    if not isinstance(value, dict) or set(value) != {"job"}:
        raise APIError("invalid_claim_schema")
    data = value["job"]
    if data is None:
        return None
    required = {"id", "target", "scope_hash", "terms_hash", "expires_at", "lease", "lease_until"}
    if not isinstance(data, dict) or set(data) != required:
        raise APIError("invalid_job_schema")
    job_id = data["id"]
    if isinstance(job_id, bool) or not isinstance(job_id, int) or not 1 <= job_id <= MAX_JOB_ID:
        raise APIError("invalid_job_id")
    target = data["target"]
    if not isinstance(target, str) or not target or len(target) > 4096:
        raise APIError("invalid_target")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in target):
        raise APIError("invalid_target")
    scope_hash = data["scope_hash"]
    terms_hash = data["terms_hash"]
    if not isinstance(scope_hash, str) or not HASH_RE.fullmatch(scope_hash):
        raise APIError("invalid_scope_hash")
    if not isinstance(terms_hash, str) or not HASH_RE.fullmatch(terms_hash):
        raise APIError("invalid_terms_hash")
    try:
        _scope, normalized_target = RequestOrigin.from_target(target)
    except ValueError as exc:
        raise APIError("invalid_target") from exc
    if target != normalized_target or hashlib.sha256(target.encode("utf-8")).hexdigest() != scope_hash:
        raise APIError("scope_binding_mismatch")
    lease = data["lease"]
    if not isinstance(lease, str) or not LEASE_RE.fullmatch(lease):
        raise APIError("invalid_lease")
    expires_at = _parse_iso8601(data["expires_at"], "expiry")
    lease_until = _parse_iso8601(data["lease_until"], "lease_until")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_at <= now or lease_until <= now:
        raise APIError("stale_claim")
    if lease_until > expires_at or (lease_until - now).total_seconds() > MAX_LEASE_SECONDS:
        raise APIError("invalid_lease_bounds")
    return JobClaim(job_id, target, scope_hash, terms_hash, expires_at, lease, lease_until)


def validate_control_task(value, *, now: datetime | None = None) -> ControlTask | None:
    if not isinstance(value, dict) or set(value) != {"task"}:
        raise APIError("invalid_claim_schema")
    data = value["task"]
    if data is None:
        return None
    required = {"id", "target", "scope_hash", "method", "expires_at", "lease", "lease_until"}
    if not isinstance(data, dict) or set(data) != required:
        raise APIError("invalid_job_schema")
    # The binding rules are the scan claim's: same target normalization, hash, lease and bounds.
    claim = validate_claim(
        {"job": {**{k: data[k] for k in ("id", "target", "scope_hash", "expires_at", "lease", "lease_until")}, "terms_hash": "0" * 64}},
        now=now,
    )
    if data["method"] not in CONTROL_METHODS:
        raise APIError("invalid_control_method")
    return ControlTask(claim.job_id, claim.target, claim.scope_hash, data["method"], claim.expires_at, claim.lease, claim.lease_until)


class APIClient:
    """One-shot API calls to the fixed CompleteTech HTTPS origin."""

    def __init__(self, secret: bytes, *, transport=None, clock=time.time, nonce_factory=None):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("invalid_api_secret")
        self._secret = secret
        self._clock = clock
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        self._transport = transport or PinnedOpener(RequestOrigin(API_HOST, "https", 443))

    def post(self, route: str, payload, *, timeout: float = 10.0):
        try:
            raw_body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise APIError("invalid_api_payload") from exc
        return self.post_raw(route, raw_body, timeout=timeout)

    def post_raw(self, route: str, raw_body: bytes, *, timeout: float = 10.0):
        if route not in ROUTES:
            raise APIError("invalid_route")
        if not isinstance(raw_body, bytes) or len(raw_body) > API_MAX_BODY:
            raise APIError("api_payload_too_large")
        timestamp = int(self._clock())
        nonce = self._nonce_factory()
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise APIError("invalid_nonce")
        headers = auth_headers(self._secret, timestamp, nonce, route, raw_body)
        full_url = API_SITE_URL + "/wp-json" + route
        request = Request(full_url, data=raw_body, headers=headers, method="POST")
        try:
            response = self._transport.open(request, timeout=timeout)
        except (http.client.HTTPException, OSError, URLError, TimeoutError, ValueError) as exc:
            raise APIError("api_network_error") from exc
        try:
            with response:
                raw_response = response.read(API_MAX_RESPONSE + 1)
                status = response.code
        except (http.client.HTTPException, OSError, TimeoutError) as exc:
            raise APIError("api_network_error") from exc
        if len(raw_response) > API_MAX_RESPONSE:
            raise APIError("api_response_too_large", status=status)
        try:
            decoded = json.loads(raw_response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        if not 200 <= status < 300:
            raise APIError(f"api_http_{status}", status=status, payload=decoded if isinstance(decoded, dict) else None)
        if not isinstance(decoded, dict):
            raise APIError("invalid_api_response", status=status)
        return decoded

    def claim(self) -> JobClaim | None:
        response = self.post("/ct-scan/v1/claim", {})
        return validate_claim(response)

    def start(self, claim: JobClaim) -> bool:
        response = self.post(
            "/ct-scan/v1/start",
            {"id": claim.job_id, "lease": claim.lease, "scope_hash": claim.scope_hash},
        )
        return type(response.get("ok")) is bool and response["ok"] is True

    def admit(self, claim: JobClaim, kind: str) -> dict:
        """Ask WordPress to admit one request ("http") or report liveness ("probe").

        A short timeout keeps a slow store from stalling the supervisor; a timeout is a refusal.
        """
        if kind not in {"http", "probe", "control", "control_probe"}:
            raise APIError("invalid_admission_kind")
        return self.post(
            "/ct-scan/v1/admit",
            {"id": claim.job_id, "lease": claim.lease, "scope_hash": claim.scope_hash, "kind": kind},
            timeout=5.0,
        )

    def control_claim(self) -> ControlTask | None:
        response = self.post("/ct-scan/v1/control/claim", {})
        return validate_control_task(response)

    def control_result(self, task: ControlTask, outcome: str, observed: list[str]) -> dict:
        if outcome not in CONTROL_OUTCOMES or not isinstance(observed, list):
            raise APIError("invalid_control_result")
        return self.post(
            "/ct-scan/v1/control/result",
            {
                "id": task.job_id,
                "lease": task.lease,
                "scope_hash": task.scope_hash,
                "method": task.method,
                "outcome": outcome,
                "observed": observed,
            },
        )

    def result(self, body: bytes) -> dict:
        response = self.post_raw("/ct-scan/v1/result", body)
        return response
