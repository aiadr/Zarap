"""Checks that a freshly started sing-box is given time to open its port.

procd returns from a restart once it has signalled the service, not once the
service is listening, and sing-box logs "started (0.22s)". Probing immediately
failed a working configuration and rolled it back. check_runtime is run here
under ucode against stubs whose listener only appears after a few probes.
Skipped when no ucode interpreter is available; CI builds one.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_parse_vless import find_ucode, lift


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "luci-app-zarap/root/usr/share/rpcd/ucode/zarap.uc"

# The listener shows up only from this probe onwards, standing in for a service
# that is still binding.
STUBS = """
let probes = 0;
function capture(command) {
	if (index(command, 'ss -H') >= 0) {
		probes++;
		return { code: 0, output: probes >= %d
			? 'tcp LISTEN 0 0 0.0.0.0:7893 users:(("sing-box",pid=1,fd=7))'
			: '' };
	}
	return { code: 0, output: '' };
}
function system(command) {
	return 0;
}
"""


class RuntimeCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        cls.source = BACKEND.read_text()

    def run_check(self, appears_at, wait_seconds):
        script = "%s\n%s\nprintf('%%J', { health: check_runtime(true, %d), probes: probes });\n" % (
            STUBS % appears_at,
            "\n".join(lift(self.source, name)
                      for name in ("tproxy_listening", "check_runtime")),
            wait_seconds)
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_waiting_finds_a_listener_that_is_still_binding(self):
        result = self.run_check(appears_at=3, wait_seconds=5)
        self.assertTrue(result["health"]["listener"])
        self.assertTrue(result["health"]["ok"])

    def test_the_same_service_fails_the_check_without_waiting(self):
        # Demonstrates the bug the wait fixes rather than just the fix.
        result = self.run_check(appears_at=3, wait_seconds=0)
        self.assertFalse(result["health"]["listener"])
        self.assertFalse(result["health"]["ok"])
        self.assertEqual(result["probes"], 1)

    def test_an_immediate_listener_costs_no_extra_probe(self):
        result = self.run_check(appears_at=1, wait_seconds=5)
        self.assertTrue(result["health"]["listener"])
        self.assertEqual(result["probes"], 1)

    def test_waiting_is_bounded_when_the_port_never_opens(self):
        result = self.run_check(appears_at=99, wait_seconds=3)
        self.assertFalse(result["health"]["listener"])
        self.assertEqual(result["probes"], 4)  # one probe plus three retries


if __name__ == "__main__":
    unittest.main()
