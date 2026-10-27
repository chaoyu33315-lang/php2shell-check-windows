"""Connection-time scope and public-address enforcement for worker requests."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


MAX_URL_LENGTH = 4096


def _canonical_host(value: str) -> str:
    if not value or "%" in value or value.endswith("."):
        raise ValueError("invalid_host")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            host = value.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError) as exc:
            raise ValueError("invalid_host") from exc
        labels = host.split(".")
        label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
        if (
            not host
            or len(host) > 253
            or len(labels) < 2
            or any(not label_pattern.fullmatch(label) for label in labels)
        ):
            raise ValueError("invalid_host")
        return host
    raise ValueError("ip_literal_not_allowed")


def _effective_port(parts) -> int:
    try:
        explicit = parts.port
    except ValueError as exc:
        raise ValueError("invalid_port") from exc
    if explicit is None:
        return 443 if parts.scheme.lower() == "https" else 80
    return explicit


def _host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


@dataclass(frozen=True)
class RequestOrigin:
    """One authorized hostname with a narrowly defined HTTP-to-HTTPS upgrade."""

    hostname: str
    initial_scheme: str
    initial_port: int
    upgraded: bool = field(default=False, compare=False, repr=False)

    @classmethod
    def from_target(cls, value: str) -> tuple["RequestOrigin", str]:
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ValueError("invalid_target")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("invalid_target")
        try:
            parts = urlsplit(value)
            host_raw = parts.hostname
            scheme = parts.scheme.lower()
            port = _effective_port(parts)
        except ValueError as exc:
            raise ValueError("invalid_target") from exc
        if scheme not in {"http", "https"} or not host_raw:
            raise ValueError("invalid_target")
        if parts.username is not None or parts.password is not None:
            raise ValueError("invalid_target")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ValueError("target_must_be_origin" )
        if (scheme, port) not in {("http", 80), ("https", 443)}:
            raise ValueError("invalid_port")
        host = _canonical_host(host_raw)
        origin = cls(host, scheme, port)
        explicit_port = parts.port
        port_suffix = f":{explicit_port}" if explicit_port is not None and explicit_port != port else ""
        normalized = f"{scheme}://{_host_for_url(host)}{port_suffix}/"
        return origin, normalized

    def validate_request(self, value: str, *, mark_upgrade: bool = True) -> tuple[str, int, str, str]:
        if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
            raise ValueError("request_out_of_scope")
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("request_out_of_scope")
        try:
            parts = urlsplit(value)
            raw_host = parts.hostname
            scheme = parts.scheme.lower()
            port = _effective_port(parts)
        except ValueError as exc:
            raise ValueError("request_out_of_scope") from exc
        if scheme not in {"http", "https"} or not raw_host:
            raise ValueError("request_out_of_scope")
        if parts.username is not None or parts.password is not None:
            raise ValueError("request_out_of_scope")
        try:
            host = _canonical_host(raw_host)
        except ValueError as exc:
            raise ValueError("request_out_of_scope") from exc
        if host != self.hostname:
            raise ValueError("request_out_of_scope")
        if (scheme, port) not in {("http", 80), ("https", 443)}:
            raise ValueError("request_out_of_scope")
        if self.initial_scheme == "https":
            if (scheme, port) != ("https", 443):
                raise ValueError("request_out_of_scope")
        elif scheme == "https":
            if (self.initial_port, port) != (80, 443):
                raise ValueError("request_out_of_scope")
            if mark_upgrade:
                object.__setattr__(self, "upgraded", True)
        else:
            if self.upgraded:
                raise ValueError("request_downgrade_blocked")
            if (self.initial_scheme, self.initial_port) != ("http", 80):
                raise ValueError("request_out_of_scope")
        target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        return scheme, port, host, target


# Explicit special-purpose ranges, listed rather than inferred: Python's ipaddress `is_global`
# differs between versions (3.10 through 3.14 disagree on several of these), and a destination
# check must not depend on the interpreter. Anything in these ranges is never a customer's site.
DENIED_V4 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",  # "this" network
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, cloud metadata
        "172.16.0.0/12",
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes the broadcast address
    )
)
DENIED_V6 = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",  # IPv4-mapped
        "64:ff9b::/96",  # NAT64
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments, includes Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "3fff::/20",  # documentation (RFC 9637)
        "5f00::/16",  # SRv6 SIDs
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)


def _public_addresses(host: str, port: int, resolver=socket.getaddrinfo):
    """Resolve afresh and reject the entire answer set if any address is non-public."""
    try:
        answers = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise socket.gaierror("DNS lookup failed") from exc
    if not answers:
        raise socket.gaierror("DNS returned no addresses")
    checked = []
    seen = set()
    for answer in answers:
        if len(answer) < 5:
            raise ValueError("invalid_dns_answer")
        family, socktype, _protocol, _canonname, sockaddr = answer
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype not in {0, socket.SOCK_STREAM}:
            raise ValueError("invalid_dns_answer")
        try:
            text = sockaddr[0]
            if "%" in text:
                raise ValueError("non_public_address")
            address = ipaddress.ip_address(text)
        except (IndexError, ValueError) as exc:
            raise ValueError("invalid_dns_answer") from exc
        unsafe = (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or address.is_private
        )
        if isinstance(address, ipaddress.IPv4Address):
            unsafe = unsafe or any(address in network for network in DENIED_V4)
        if isinstance(address, ipaddress.IPv6Address):
            unsafe = unsafe or address.ipv4_mapped is not None or address.is_site_local
            unsafe = unsafe or address not in ipaddress.ip_network("2000::/3")
            unsafe = unsafe or any(address in network for network in DENIED_V6)
        if unsafe:
            raise ValueError("non_public_address")
        key = (family, address.compressed)
        if key not in seen:
            seen.add(key)
            checked.append((family, address.compressed))
    if not checked:
        raise ValueError("invalid_dns_answer")
    return checked


def _connect_socket(family, address: str, port: int, timeout, source_address=None):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
        sock.connect(sockaddr)
        return sock
    except BaseException:
        sock.close()
        raise


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, *, pinned_family, pinned_address, timeout=None, before_connect=None, **kwargs):
        super().__init__(host, port, timeout=timeout, **kwargs)
        self._pinned_family = pinned_family
        self._pinned_address = pinned_address
        self._before_connect = before_connect

    def connect(self):
        if self._before_connect is not None:
            self._before_connect()
        self.sock = _connect_socket(
            self._pinned_family, self._pinned_address, self.port, self.timeout, self.source_address
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, *, pinned_family, pinned_address, timeout=None, context=None, before_connect=None, **kwargs):
        super().__init__(host, port, timeout=timeout, context=context or ssl.create_default_context(), **kwargs)
        self._pinned_family = pinned_family
        self._pinned_address = pinned_address
        self._before_connect = before_connect

    def connect(self):
        if self._tunnel_host:
            raise OSError("tunnels are disabled")
        if self._before_connect is not None:
            self._before_connect()
        raw = _connect_socket(
            self._pinned_family, self._pinned_address, self.port, self.timeout, self.source_address
        )
        try:
            # Keep the authorized hostname for SNI and certificate-name verification.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class _ManagedResponse:
    def __init__(self, response, connection, on_close=None):
        self._response = response
        self._connection = connection
        self._on_close = on_close
        self.code = response.status
        self.headers = response.headers

    def read(self, size=-1):
        return self._response.read(size)

    def close(self):
        try:
            self._response.close()
        finally:
            try:
                self._connection.close()
            finally:
                if self._on_close is not None:
                    self._on_close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class PinnedOpener:
    """urllib-compatible single request transport with no proxies or auto-redirects.

    With an admission ``guard`` (the scanner child), every request first obtains a
    one-request admission from the supervisor, re-checks that it is still fresh
    immediately before connecting, and reports completion. Without a guard (the
    fixed WordPress API client and offline tests) no target is contacted.
    """

    def __init__(self, scope: RequestOrigin, *, resolver=socket.getaddrinfo, ssl_context=None, guard=None):
        self.scope = scope
        self.resolver = resolver
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.guard = guard

    def open(self, request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        # Scope validation happens before DNS resolution, so cross-host redirects do not
        # make even a DNS request for an unauthorized hostname.
        scheme, port, host, target = self.scope.validate_request(url)
        answers = _public_addresses(host, port, self.resolver)
        family, address = answers[0]
        guard = self.guard
        if guard is not None:
            # No grant, no connection. Raises before any socket is opened.
            guard.admit()
        try:
            connection_type = PinnedHTTPSConnection if scheme == "https" else PinnedHTTPConnection
            kwargs = {"pinned_family": family, "pinned_address": address, "timeout": timeout}
            if guard is not None:
                kwargs["before_connect"] = guard.ensure_fresh
            if scheme == "https":
                kwargs["context"] = self.ssl_context
            connection = connection_type(host, port, **kwargs)
            headers = dict(request.header_items()) if hasattr(request, "header_items") else {}
            headers["Connection"] = "close"
            method = request.get_method() if hasattr(request, "get_method") else "GET"
            body = getattr(request, "data", None)
            try:
                connection.request(method, target, body=body, headers=headers)
                response = connection.getresponse()
                return _ManagedResponse(response, connection, guard.done if guard is not None else None)
            except BaseException:
                connection.close()
                raise
        except BaseException:
            if guard is not None:
                guard.done()
            raise
