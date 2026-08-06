"""Feeds the backend's generated firewall rules to nftables.

The shipped 90-zarap.nft is already checked by CI, but it carries no runtime
data. What actually reaches the router is built by nft_config from the client
list and from the LAN networks read over ubus, and those LAN prefixes sit
inside the static RFC1918 and fc00::/7 entries. Generate the real thing and let
nft parse it. Skipped when ucode or nft is unavailable; CI has both.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_parse_vless import find_ucode, lift


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "luci-app-zarap/root/usr/share/rpcd/ucode/zarap.uc"

# direct_networks reads the LAN through ubus, which is absent off the router.
UBUS_STUB = """
function connect() {
	return {
		call: function(object, method) {
			return {
				'ipv4-address': [ { address: '192.168.10.1', mask: 24 } ],
				'ipv6-prefix': [ { address: 'fd00:abcd::', mask: 64 } ]
			};
		},
		disconnect: function() {}
	};
}
"""

CLIENTS = ("[ { ip: '192.168.10.167', mac: 'EA:76:7F:24:D1:79' },"
           "  { ip: '192.168.10.42', mac: '00:11:22:33:44:55' } ]")


class NftRulesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        cls.nft = shutil.which("nft") or "/usr/sbin/nft"
        if not Path(cls.nft).is_file():
            raise unittest.SkipTest("no nft binary available")
        source = BACKEND.read_text()
        cls.prelude = UBUS_STUB + "\n".join(
            lift(source, name)
            for name in ("valid_ipv4", "network_v4", "nft_set",
                         "direct_networks", "nft_config"))

    def generate(self, clients=CLIENTS):
        script = "%s\nprint(nft_config(%s, 7893));\n" % (self.prelude, clients)
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout
        finally:
            os.unlink(path)

    def check(self, ruleset):
        with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as handle:
            handle.write("table inet zarap_check {\n%s}\n" % ruleset)
            path = handle.name
        try:
            return subprocess.run([self.nft, "-c", "-f", path],
                                  capture_output=True, text=True)
        finally:
            os.unlink(path)

    def test_nftables_accepts_the_generated_ruleset(self):
        # The LAN sits inside 192.168.0.0/16 and the prefix inside fc00::/7, so
        # without auto-merge nft rejects both sets as conflicting intervals.
        done = self.check(self.generate())
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_nftables_accepts_a_ruleset_with_no_clients(self):
        done = self.check(self.generate("[]"))
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_generated_sets_carry_the_client_data(self):
        ruleset = self.generate()
        self.assertIn("192.168.10.167", ruleset)
        self.assertIn("EA:76:7F:24:D1:79", ruleset)
        # The LAN discovered over ubus has to be reachable directly.
        self.assertIn("192.168.10.0/24", ruleset)

    def test_tproxy_and_kill_switch_rules_are_present(self):
        ruleset = self.generate()
        self.assertIn("tproxy ip to 127.0.0.1:7893", ruleset)
        self.assertIn("ip saddr @zarap_clients_v4 reject", ruleset)
        self.assertIn("ether saddr @zarap_clients_mac ether type ip6 reject", ruleset)


if __name__ == "__main__":
    unittest.main()
