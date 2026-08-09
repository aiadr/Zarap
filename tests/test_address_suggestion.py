"""Runs the real address suggester from the backend under a ucode interpreter.

A device that never held a lease has no address, and a rule cannot name it
without one. The suggester is what keeps that from being a dead end, so it is
lifted out of the rpcd plugin and run against stubbed leases rather than a copy
of its arithmetic. Skipped when no ucode interpreter is available; CI builds one.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_parse_vless import find_ucode, lift


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "luci-app-zarap/root/usr/share/rpcd/ucode/zarap.uc"


class AddressSuggestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        cls.prelude = "\n".join(
            lift(source, name) for name in
            ("valid_ipv4", "ipv4_number", "ipv4_text", "address_suggester"))

    def suggest(self, count, router, mask, static=(), dynamic=()):
        """Ask for `count` addresses with the given LAN and leases in place."""
        stubs = """
function lan_ipv4() { return %s; }
function static_leases() { return { by_ip: %s, by_mac: {} }; }
function current_dhcp_leases() { return %s; }
""" % (
            json.dumps({"address": router, "mask": mask}) if router else "null",
            json.dumps({ip: {"ip": ip} for ip in static}),
            json.dumps({"00:00:00:00:00:%02x" % n: {"ip": ip}
                        for n, ip in enumerate(dynamic)}),
        )
        script = "%s\n%s\nlet next = address_suggester();\nfor (let i = 0; i < %d; i++)\n\tprint(next(), '\\n');\n" % (
            stubs, self.prelude, count)
        with tempfile.NamedTemporaryFile("w", suffix=".uc") as handle:
            handle.write(script)
            handle.flush()
            done = subprocess.run([self.ucode, handle.name],
                                  capture_output=True, text=True, check=True)
        return done.stdout.strip().split("\n")

    def test_skips_the_router_and_every_lease(self):
        self.assertEqual(
            self.suggest(2, "192.168.10.1", 24,
                         static=["192.168.10.2"], dynamic=["192.168.10.3"]),
            ["192.168.10.4", "192.168.10.5"])

    def test_hands_out_a_different_address_each_time(self):
        # Two devices added in one go must not be pinned to one address, which
        # dnsmasq would refuse and the apply would roll back.
        addresses = self.suggest(3, "192.168.1.1", 24)
        self.assertEqual(addresses, ["192.168.1.2", "192.168.1.3", "192.168.1.4"])
        self.assertEqual(len(set(addresses)), 3)

    def test_stays_inside_the_lan_prefix(self):
        self.assertEqual(self.suggest(1, "10.9.8.7", 16), ["10.9.0.1"])

    def test_offers_nothing_when_ubus_cannot_name_the_lan(self):
        # Better an empty field the user fills than an address off the subnet:
        # the backend would refuse it anyway, and it would look like ours.
        self.assertEqual(self.suggest(1, None, 24), [""])

    def test_offers_nothing_once_the_subnet_is_full(self):
        taken = ["192.168.1.%d" % n for n in range(1, 255)]
        self.assertEqual(self.suggest(1, "192.168.1.1", 24, static=taken), [""])


if __name__ == "__main__":
    unittest.main()
