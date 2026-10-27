"""Real HTTP protocol test against the internal disposable WP fixture only.

The injected transport is intentionally confined to this test. It is never
available through production worker configuration. Run after explicit fixture
confirmation; no website scanning takes place.
"""
import dataclasses
import http.client
import json
import os
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from urllib.parse import urlsplit, urlencode

from integrations.worker.admission import AdmissionDenied, AdmissionGate, parse_grant
from integrations.worker.protocol import APIClient, APIError
from integrations.worker.runner import SubprocessRunner
from integrations.worker.network import RequestOrigin
from wordpress_check import Checker


# The disposable Compose service is "wordpress:80"; a local run may override both.
FIXTURE_HOST = os.environ.get('CT_FIXTURE_HOST', 'wordpress')
FIXTURE_PORT = int(os.environ.get('CT_FIXTURE_PORT', '80'))


class Response:
    def __init__(self, response, connection):
        self.response = response
        self.connection = connection
        self.code = response.status

    def read(self, limit):
        return self.response.read(limit)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()


class FixtureTransport:
    def open(self, request, timeout):
        route = urlsplit(request.full_url).path.removeprefix('/wp-json')
        assert route in {'/ct-scan/v1/claim', '/ct-scan/v1/start', '/ct-scan/v1/admit', '/ct-scan/v1/result'}
        connection = http.client.HTTPConnection(FIXTURE_HOST, FIXTURE_PORT, timeout=timeout)
        connection.request('POST', '/?rest_route=' + route, body=request.data, headers=dict(request.header_items()))
        response = connection.getresponse()
        return Response(response, connection)


class SyntheticResponse:
    def __init__(self, url):
        self.code = 200
        self.headers = Message()
        self.headers['Content-Type'] = 'text/plain' if url.endswith('/robots.txt') else 'text/html'
        self.headers['X-Powered-By'] = 'PHP/8.3.30'
        self.body = b'User-agent: *\nAllow: /\n' if url.endswith('/robots.txt') else b'<html><title>&lt;script&gt;fixture&lt;/script&gt;</title></html>'

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class SyntheticOpener:
    def open(self, request, timeout):
        assert urlsplit(request.full_url).hostname == 'http-fixture.example.com'
        return SyntheticResponse(request.full_url)


api = APIClient(b'fixture-' * 8, transport=FixtureTransport())
token = os.environ.get('CT_FIXTURE_TOKEN')
if token:
    assert re.fullmatch('[a-f0-9]{64}', token)
    connection = http.client.HTTPConnection(FIXTURE_HOST, FIXTURE_PORT, timeout=10)
    connection.request('POST', '/?rest_route=/ct-scan/v1/claim', '{}', {'Content-Type': 'application/json'})
    response = connection.getresponse()
    response.read()
    assert response.status == 401, 'Unauthenticated claim was accepted'
    connection.close()
    nonce = secrets.token_hex(16)
    replay_client = APIClient(b'fixture-' * 8, transport=FixtureTransport(), nonce_factory=lambda: nonce)
    assert replay_client.claim() is None
    try:
        replay_client.claim()
    except APIError as error:
        assert error.status == 409
    else:
        raise AssertionError('Replayed signed request accepted')
    connection = http.client.HTTPConnection(FIXTURE_HOST, FIXTURE_PORT, timeout=10)
    connection.request('GET', '/wp-admin/admin-post.php?action=ct_scan_confirm&token=' + token)
    response = connection.getresponse()
    page = response.read().decode()
    assert response.status == 200
    connection.close()
    assert 'https://http-fixture.example.com/' in page
    assert api.claim() is None, 'GET prefetch authorized a scan'
    fields = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', page))
    form = urlencode(fields)
    for expected_status in (200, 410):
        connection = http.client.HTTPConnection(FIXTURE_HOST, FIXTURE_PORT, timeout=10)
        connection.request('POST', '/wp-admin/admin-post.php', form,
                           {'Content-Type': 'application/x-www-form-urlencoded'})
        response = connection.getresponse()
        response.read()
        assert response.status == expected_status, 'Confirmation replay was accepted'
        connection.close()

def concurrent_claim(_):
    try:
        return api.claim()
    except APIError as error:
        assert error.status == 503, error.slug
        return None  # Contending claim fails closed while the lock is held.


with ThreadPoolExecutor(max_workers=2) as pool:
    claims = [value for value in pool.map(concurrent_claim, range(2)) if value is not None]
assert len(claims) == 1, 'Concurrent claims did not yield exactly one lease'
claim = claims[0]
assert claim and claim.target == 'https://http-fixture.example.com/'
assert api.claim() is None, 'Concurrent worker obtained a second lease'
assert api.start(claim)

# Per-request admission over the real signed HTTP boundary.
assert api.admit(claim, 'probe') == {'ok': True, 'live': True}
first = parse_grant(api.admit(claim, 'http'))
assert (first.sequence, first.valid_seconds, first.timeout_seconds, first.remaining) == (1, 1.0, 10.0, 19)
try:
    api.admit(claim, 'http')
except APIError as error:
    assert error.status == 429 and error.payload['reason'] == 'rate_wait', error.payload
else:
    raise AssertionError('A second admission inside the pacing interval was granted')
second = AdmissionGate(api, claim).admit()  # waits out the interval, then is granted
assert second.sequence == 2 and second.remaining == 18
bad = dict(id=claim.job_id, lease='f' * 64, scope_hash=claim.scope_hash, kind='http')
try:
    api.post('/ct-scan/v1/admit', bad)
except APIError as error:
    assert error.status == 410 and error.payload['reason'] == 'lease_invalid_or_expired', error.payload
else:
    raise AssertionError('Admission with a foreign lease was granted')
checker = Checker(delay=0)
checker.opener = SyntheticOpener()
result = dataclasses.asdict(checker.check(claim.target))
scope, _ = RequestOrigin.from_target(claim.target)
SubprocessRunner.validate_result(result, claim.target, scope)
body = json.dumps({'id': claim.job_id, 'lease': claim.lease, 'scope_hash': claim.scope_hash,
                   'outcome': 'completed', 'result': result, 'error': '',
                   'checker_revision': 'a' * 40}, separators=(',', ':')).encode()
assert api.result(body) == {'ok': True}
assert api.result(body) == {'ok': True}, 'Identical receipt retry must be idempotent'
assert api.claim() is None
for kind in ('http', 'probe'):
    try:
        api.admit(claim, kind)
    except APIError as error:
        assert error.status == 410 and error.payload['reason'] == 'job_not_running', error.payload
    else:
        raise AssertionError('A finished job was admitted')
try:
    AdmissionGate(api, claim).admit()
except AdmissionDenied as denied:
    assert denied.slug == 'job_not_running'
else:
    raise AssertionError('The gate admitted a finished job')
print('HTTP claim/start/admit/result/receipt-retry passed; scanner used synthetic responses only.')
