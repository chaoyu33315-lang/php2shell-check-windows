"""Real HTTP test of the exact-target control gate against the internal disposable WP fixture only.

Run after `test-http-fixture.php setup control`. The customer's pages are driven over HTTP; the
worker side uses the real signed API client. The challenge value is supplied by this test (no
DNS lookup or website request is made): it exercises the WordPress boundary, not a target.
"""
import http.client
import os
import re
from urllib.parse import urlencode

from integrations.worker.admission import AdmissionGate
from integrations.worker.protocol import APIClient, APIError

HOST = os.environ.get('CT_FIXTURE_HOST', 'wordpress')
PORT = int(os.environ.get('CT_FIXTURE_PORT', '80'))


class Response:
    def __init__(self, response, connection):
        self.response, self.connection, self.code = response, connection, response.status

    def read(self, limit):
        return self.response.read(limit)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.connection.close()


class Transport:
    def open(self, request, timeout):
        from urllib.parse import urlsplit
        route = urlsplit(request.full_url).path.removeprefix('/wp-json')
        connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
        connection.request('POST', '/?rest_route=' + route, body=request.data, headers=dict(request.header_items()))
        return Response(connection.getresponse(), connection)


def page(method, path, body=None):
    connection = http.client.HTTPConnection(HOST, PORT, timeout=10)
    headers = {'Content-Type': 'application/x-www-form-urlencoded'} if body is not None else {}
    connection.request(method, path, body, headers)
    response = connection.getresponse()
    text = response.read().decode()
    connection.close()
    return response.status, text


def hidden(text):
    return dict(re.findall(r'name="([^"]+)" value="([^"]*)"', text))


api = APIClient(b'fixture-' * 8, transport=Transport())
token = os.environ['CT_FIXTURE_TOKEN']
assert re.fullmatch('[a-f0-9]{64}', token)

# 1. Mailbox confirmation does not queue: the job waits for control of the website.
status, text = page('GET', '/wp-admin/admin-post.php?action=ct_scan_confirm&token=' + token)
assert status == 200
status, text = page('POST', '/wp-admin/admin-post.php', urlencode(hidden(text)))
assert status == 200 and 'Show control of your website' in text, text[:300]
challenge = re.search(r'ct-scan-verify=([a-f0-9]{64})', text).group(1)
form = hidden(text)
assert form['ctl'] != challenge and form['job'] and form['_wpnonce'], 'The page capability must not be the published challenge'
assert api.claim() is None, 'A job awaiting target control was claimable for scanning'
assert api.control_claim() is None, 'A check ran before the customer asked for one'

# 2. The customer asks for a DNS check; a second request is refused while it is outstanding.
status, text = page('POST', '/wp-admin/admin-post.php', urlencode(dict(form, method='dns_txt')))
assert status == 200 and 'scheduled' in text, text[:300]
status, text = page('POST', '/wp-admin/admin-post.php', urlencode(dict(form, method='https_file')))
assert 'already scheduled' in text, text[:300]
status, _ = page('POST', '/wp-admin/admin-post.php', urlencode(dict(form, method='dns_txt', ctl='f' * 64)))
assert status == 410, 'A wrong page capability reached the control handler'
status, _ = page('POST', '/wp-admin/admin-post.php', urlencode(dict(form, method='dns_txt', ctl=challenge)))
assert status == 410, 'The published challenge value opened the control page'
status, _ = page('POST', '/wp-admin/admin-post.php', urlencode({k: v for k, v in dict(form, method='dns_txt').items() if k != '_wpnonce'}))
assert status == 403, 'A control request without its nonce was accepted'

# 3. The worker claims it, is admitted exactly once, and reports what it saw.
task = api.control_claim()
assert task and task.method == 'dns_txt' and task.target == 'https://http-fixture.example.com/'
assert api.control_claim() is None, 'A checking job was claimed twice'
gate = AdmissionGate(api, task, kind='control')
grant = gate.admit()
assert (grant.sequence, grant.remaining) == (1, 2)
try:
    api.control_result(task, 'observed', ['ct-scan-verify=' + 'a' * 64])
    verified = None
except APIError as error:
    verified = error
assert verified is None  # a wrong value is a recorded failure, not an error
assert api.claim() is None, 'A wrong challenge value released the job'
text = page('GET', '/wp-admin/admin-post.php?' + urlencode({'action': 'ct_scan_control', 'job': form['job'], 'ctl': form['ctl']}))[1]
assert 'ct-scan-verify=' + challenge in text, 'The returning customer is shown the same challenge'
assert 'Checks used: 1 of 3' in text, text[:400]

# 4. One minute later the customer asks again; the right value releases the job for scanning.
age = os.environ.get('CT_FIXTURE_AGE_COMMAND')
if age:  # CI ages the fixture row by a minute instead of sleeping; local runs may wait
    import subprocess
    subprocess.run(age, shell=True, check=True)
else:
    import time
    time.sleep(61)
fresh = hidden(text)
status, text = page('POST', '/wp-admin/admin-post.php', urlencode(dict(fresh, method='dns_txt')))
assert 'scheduled' in text, text[:300]
task = api.control_claim()
assert task, 'The second check was not scheduled'
AdmissionGate(api, task, kind='control').admit()
assert api.control_result(task, 'observed', ['ct-scan-verify=' + challenge]) == {'ok': True, 'verified': True}
claim = api.claim()
assert claim and claim.target == 'https://http-fixture.example.com/', 'A verified job was not claimable'
print('HTTP target-control gate passed; no DNS lookup or website request was made.')
