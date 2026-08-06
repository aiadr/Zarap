"""Runs resource_conflict against recorded nftables output.

nft renders a packet mark zero-padded — "0x00005a52", not "0x5a52" — so the
guard that is meant to stop Zarap from taking a mark another ruleset already
uses matched nothing at all. The fixtures here are genuine `nft -a list`
output, so the check is tested against the format nft really produces.
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
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name):
    return (FIXTURES / name).read_text()


class ResourceConflictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        cls.source = BACKEND.read_text()

    def run_conflict(self, ruleset):
        """Stub every command resource_conflict shells out to.

        Only the nftables ruleset varies; the port, route and rule probes come
        back empty, which is the state of a router with nothing else running.
        """
        stubs = """
function capture(command) {
	if (index(command, 'list chain inet fw4 zarap_prerouting') >= 0)
		return { code: 0, output: %s };
	if (index(command, 'list chain inet fw4 zarap_protect_tproxy') >= 0)
		return { code: 0, output: %s };
	if (index(command, 'list ruleset') >= 0)
		return { code: 0, output: %s };
	return { code: 0, output: '' };
}
function saved_proxy_config() { return { server: 'proxy.example.test' }; }
""" % (json.dumps(fixture("nft-chain-prerouting.txt")),
       json.dumps(fixture("nft-chain-protect.txt")),
       json.dumps(ruleset))
        script = "%s\n%s\nprintf('%%J', resource_conflict());\n" % (
            stubs,
            "\n".join(lift(self.source, name)
                      for name in ("result_error", "resource_conflict")))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_zarap_own_rules_are_not_a_conflict(self):
        # zarap_protect_tproxy carries the mark too; counting only
        # zarap_prerouting as ours would fail every apply against itself.
        result = self.run_conflict(fixture("nft-ruleset-clean.txt"))
        self.assertTrue(result["ok"], result.get("error"))

    def test_a_foreign_rule_using_the_mark_is_reported(self):
        result = self.run_conflict(fixture("nft-ruleset-foreign.txt"))
        self.assertFalse(result["ok"])
        self.assertIn("0x5a52", result["error"])

    def test_the_fixtures_carry_the_padded_form_nft_emits(self):
        # Guards the premise: if nft ever stopped padding, matching could go
        # back to a plain substring and this test should be revisited.
        self.assertIn("0x00005a52", fixture("nft-ruleset-clean.txt"))
        self.assertNotIn("mark set 0x5a52 ", fixture("nft-ruleset-clean.txt"))


if __name__ == "__main__":
    unittest.main()
