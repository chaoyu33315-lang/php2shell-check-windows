"""Smoke-test the packaged worker with Docker --network none; no real target."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from integrations.worker.admission import AdmissionDenied
from integrations.worker.runner import SubprocessRunner, _linux_preexec_limits
from integrations.worker.service import load_secret


assert os.geteuid() == 0
with tempfile.TemporaryDirectory() as directory:
    secret = Path(directory) / 'key'
    secret.write_text('synthetic-fixture-key-' * 3)
    secret.chmod(0o600)
    assert load_secret(secret) == b'synthetic-fixture-key-' * 3
    code = '''import os,sys
assert os.getuid() == os.getgid() == 65534
assert not os.getgroups()
assert 'CT_SCAN_SECRET_FILE' not in os.environ
try:
    open(sys.argv[1]).read()
except PermissionError:
    print('scanner secret isolation passed')
else:
    raise AssertionError('scanner could read controller key')
'''
    subprocess.run([sys.executable, '-c', code, str(secret)], check=True,
                   env={'PATH': '/usr/local/bin:/usr/bin:/bin'},
                   preexec_fn=_linux_preexec_limits)

class RefusingGate:
    # With no network the lookup fails before any admission is requested; if the
    # scanner ever asked, a refusal here would fail the run.
    admits = 0

    def admit(self):
        RefusingGate.admits += 1
        raise AdmissionDenied('job_cancelled')

    def probe(self):
        return None


result = SubprocessRunner().run('https://runtime-fixture.example.invalid/', timeout=15, gate=RefusingGate())
assert RefusingGate.admits == 0, 'an admission was requested although the destination never resolved'
assert result['status'] == 'error', result['status']
assert result['php2shell_status'] == 'unknown'
assert result['php2shell_exploitability'] == 'not_tested'
print('Packaged checker ran without network access and retained unknown outcome.')
