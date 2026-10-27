"""Exact-target control checks: one DNS TXT lookup or one HTTPS file request.

These run inside the unprivileged scanner child, under the same admission guard as a
scan: the supervisor asks WordPress for an admission (``kind=control``) before the one
query, and a refusal ends the run. Limits are the disclosed ones: a fixed name or path,
no redirects, at most 4096 bytes, a ten-second timeout, one query per admission.

Everything read from the network is untrusted data: it is length-bounded, decoded
without execution, and compared by WordPress against a stored hash. The worker never
learns the expected token.
"""

from __future__ import annotations

import random
import socket
import struct
import time
from urllib.request import Request

from .admission import AdmissionRefused

CHALLENGE_PATH = "/.well-known/ct-scan-challenge.txt"
DNS_LABEL = "_ct-scan-challenge"
MAX_BYTES = 4096
TIMEOUT_SECONDS = 10.0
MAX_TXT_RECORDS = 8
USER_AGENT = "php2shell-check-control/1 (+https://complete.tech/services/website-security/)"


class ControlError(Exception):
    """A lookup or fetch that could not be completed (reported as outcome ``error``)."""


def _encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ControlError("dns_name_invalid")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    if len(out) > 255:
        raise ControlError("dns_name_invalid")
    return bytes(out)


def build_txt_query(name: str, txid: int) -> bytes:
    """A single recursive TXT/IN question."""
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", 16, 1)


def _read_name(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read a (possibly compressed) name; return (lowercased wire name, offset after it in place)."""
    labels = []
    end = None
    hops = 0
    while True:
        if offset >= len(data):
            raise ControlError("dns_malformed")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ControlError("dns_malformed")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            hops += 1
            if hops > 16 or pointer >= len(data):
                raise ControlError("dns_malformed")
            offset = pointer
            continue
        if length & 0xC0:
            raise ControlError("dns_malformed")
        offset += 1
        if length == 0:
            return b".".join(labels).lower(), (end if end is not None else offset)
        if offset + length > len(data) or len(labels) > 127:
            raise ControlError("dns_malformed")
        labels.append(data[offset : offset + length])
        offset += length


def parse_txt_response(data: bytes, txid: int, name: str) -> list[str]:
    """Return the TXT values for ``name``. NXDOMAIN or no data is an empty list.

    Truncated (TC) answers, mismatched ids or questions, other error codes and malformed
    packets raise ControlError; there is no fall back to TCP or another resolver.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12 or len(data) > MAX_BYTES:
        raise ControlError("dns_malformed")
    ident, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if ident != txid or not flags & 0x8000:
        raise ControlError("dns_mismatch")
    if flags & 0x0200:
        raise ControlError("dns_truncated")
    rcode = flags & 0x000F
    if rcode not in (0, 3):
        raise ControlError("dns_error")
    if qd != 1:
        raise ControlError("dns_mismatch")
    offset = 12
    qname, offset = _read_name(data, offset)
    if offset + 4 > len(data):
        raise ControlError("dns_malformed")
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    offset += 4
    if qname != name.rstrip(".").encode("ascii").lower() or (qtype, qclass) != (16, 1):
        raise ControlError("dns_mismatch")
    values: list[str] = []
    for _ in range(min(an, 64)):
        rname, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise ControlError("dns_malformed")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(data):
            raise ControlError("dns_malformed")
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype != 16 or rclass != 1 or rname != qname:
            continue
        parts = bytearray()
        position = 0
        while position < len(rdata):
            length = rdata[position]
            if position + 1 + length > len(rdata):
                raise ControlError("dns_malformed")
            parts.extend(rdata[position + 1 : position + 1 + length])
            position += 1 + length
        if len(values) >= MAX_TXT_RECORDS:
            raise ControlError("dns_too_many_records")
        values.append(bytes(parts).decode("utf-8", errors="replace"))
    if sum(len(v.encode("utf-8")) for v in values) > MAX_BYTES:
        raise ControlError("dns_too_large")
    return values


def system_resolver(path: str = "/etc/resolv.conf") -> tuple[str, int]:
    """The first configured nameserver. No search domains, no fallbacks."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1].split("%", 1)[0], 53
    except OSError as exc:
        raise ControlError("dns_resolver_unavailable") from exc
    raise ControlError("dns_resolver_unavailable")


def lookup_txt(host: str, resolver: tuple[str, int], guard, *, timeout: float = TIMEOUT_SECONDS, txid: int | None = None) -> list[str]:
    """One TXT lookup of ``_ct-scan-challenge.<host>`` through the configured resolver, once admitted."""
    name = f"{DNS_LABEL}.{host}"
    query_id = random.SystemRandom().randrange(1, 0x10000) if txid is None else txid
    packet = build_txt_query(name, query_id)
    family = socket.AF_INET6 if ":" in resolver[0] else socket.AF_INET
    guard.admit()
    try:
        guard.ensure_fresh()
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.sendto(packet, resolver)
            deadline = time.monotonic() + timeout  # one overall budget; stray packets cannot extend it
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControlError("dns_timeout")
                sock.settimeout(remaining)
                try:
                    data, source = sock.recvfrom(MAX_BYTES + 1)
                except socket.timeout as exc:
                    raise ControlError("dns_timeout") from exc
                except OSError as exc:
                    raise ControlError("dns_network_error") from exc
                if source[0] == resolver[0] and source[1] == resolver[1]:
                    break  # anything from another source is ignored, not trusted
        finally:
            sock.close()
    finally:
        guard.done()
    return parse_txt_response(data, query_id, name)


def fetch_challenge_file(opener, host: str, timeout: float = TIMEOUT_SECONDS) -> tuple[str, list[str]]:
    """GET the fixed challenge path once. The opener enforces scope, public addresses and admission.

    Returns (outcome, observed). Redirects are not followed: a 3xx is "not_found".
    """
    request = Request(
        f"https://{host}{CHALLENGE_PATH}",
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain", "Accept-Encoding": "identity"},
        method="GET",
    )
    try:
        stream = opener.open(request, timeout=timeout)
    except AdmissionRefused:
        raise
    except (OSError, ValueError, TimeoutError):
        return "error", []
    try:
        with stream:
            raw = stream.read(MAX_BYTES + 1)
            status = stream.code
    except (OSError, TimeoutError):
        return "error", []
    if status == 200:
        if len(raw) > MAX_BYTES:
            return "error", []
        try:
            return "observed", [raw.decode("utf-8")]
        except UnicodeDecodeError:
            return "error", []
    if status in (301, 302, 303, 307, 308, 404, 410):
        return "not_found", []
    return "error", []
