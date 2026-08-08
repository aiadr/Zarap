"""Runs the real sing-box generator from the backend under a ucode interpreter.

The generator turns uci sections into `outbounds[]` and `route.rules[]`. The
functions are lifted out of the rpcd plugin and executed against the parsed
JSON they produce, so the mapping itself is under test rather than a copy of it.
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

OUT_1 = {
    "tag": "out_1",
    "server": "nl.example.test",
    "server_port": 443,
    "uuid": "123e4567-e89b-42d3-a456-426614174000",
    "flow": "xtls-rprx-vision",
    "server_name": "cdn.example.test",
    "public_key": "0123456789abcdefghijklmnopqrstuvwxyzABCDE",
    "short_id": "a1b2",
    "fingerprint": "chrome",
}

OUT_2 = dict(OUT_1, tag="out_2", server="de.example.test", flow="", short_id="")

ADDRESSES = {
    "00:11:22:33:44:55": "192.168.1.50",
    "AA:BB:CC:DD:EE:FF": "192.168.1.51",
    "10:20:30:40:50:60": "192.168.1.61",
}


class RouteMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        constants = "\n".join(
            line for line in source.splitlines()
            if line.startswith(("const CAPTURE_PORT", "const INBOUND_TAG",
                                "const RESERVED_TAGS")))
        cls.prelude = constants + "\n" + "\n".join(
            lift(source, name) for name in
            ("valid_outbound_tag", "outbound_json", "rule_json", "sing_box_config"))

    def generate(self, outbounds, rules, final, addresses=None):
        script = "%s\nprintf('%%J', sing_box_config(%s, %s, %s, %s));\n" % (
            self.prelude,
            json.dumps(outbounds), json.dumps(rules), json.dumps(final),
            json.dumps(ADDRESSES if addresses is None else addresses))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def tags(self, config):
        return [outbound["tag"] for outbound in config["outbounds"]]

    def test_capture_without_any_policy_routes_nothing(self):
        # One connection and no rules must not quietly send the house through
        # the proxy: everything falls through to the default, which is direct.
        config = self.generate([OUT_1], [], "direct")
        self.assertEqual(config["route"]["rules"], [])
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(self.tags(config), ["out_1", "direct"])

    def test_outbound_carries_the_reality_fields(self):
        outbound = self.generate([OUT_1], [], "direct")["outbounds"][0]
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")
        self.assertTrue(outbound["tls"]["reality"]["enabled"])
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "a1b2")
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "chrome")

    def test_empty_flow_and_short_id_are_omitted(self):
        outbound = self.generate([OUT_2], [], "direct")["outbounds"][0]
        self.assertNotIn("flow", outbound)
        self.assertNotIn("short_id", outbound["tls"]["reality"])

    def test_rule_order_follows_section_order(self):
        rules = [
            {"clients": ["00:11:22:33:44:55"], "target": "out_1"},
            {"clients": ["10:20:30:40:50:60"], "target": "block"},
            {"clients": ["AA:BB:CC:DD:EE:FF"], "target": "direct"},
        ]
        emitted = self.generate([OUT_1], rules, "direct")["route"]["rules"]
        self.assertEqual(
            [rule.get("outbound") or rule.get("action") for rule in emitted],
            ["out_1", "reject", "direct"])

    def test_block_becomes_a_reject_action_and_not_an_outbound(self):
        # The special `block` outbound was deprecated in sing-box 1.11 and
        # removed in 1.13; emitting one would break on a current build.
        rules = [{"clients": ["10:20:30:40:50:60"], "target": "block"}]
        config = self.generate([OUT_1], rules, "direct")
        self.assertEqual(config["route"]["rules"][0]["action"], "reject")
        self.assertNotIn("outbound", config["route"]["rules"][0])
        self.assertNotIn("block", self.tags(config))

    def test_direct_is_declared_only_when_referenced(self):
        proxied = self.generate(
            [OUT_1], [{"clients": ["00:11:22:33:44:55"], "target": "out_1"}], "out_1")
        self.assertEqual(self.tags(proxied), ["out_1"])

        by_rule = self.generate(
            [OUT_1], [{"clients": ["00:11:22:33:44:55"], "target": "direct"}], "out_1")
        self.assertEqual(self.tags(by_rule), ["out_1", "direct"])

        by_final = self.generate([OUT_1], [], "direct")
        self.assertEqual(self.tags(by_final), ["out_1", "direct"])

    def test_final_block_appends_a_catch_all_and_keeps_a_valid_tag(self):
        config = self.generate(
            [OUT_1, OUT_2],
            [{"clients": ["00:11:22:33:44:55"], "target": "out_2"}],
            "block")
        last = config["route"]["rules"][-1]
        self.assertEqual(last["action"], "reject")
        self.assertNotIn("source_ip_cidr", last)
        # `final` takes a tag and `block` is not one, so a declared tag goes
        # there; the trailing rule is what actually blocks.
        self.assertIn(config["route"]["final"], self.tags(config))
        self.assertEqual(config["route"]["final"], "out_1")

    def test_final_proxy_routes_the_remainder_without_extra_rules(self):
        config = self.generate([OUT_1], [], "out_1")
        self.assertEqual(config["route"]["rules"], [])
        self.assertEqual(config["route"]["final"], "out_1")

    def test_several_devices_in_one_rule_give_one_element(self):
        rules = [{"clients": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"],
                  "target": "out_1"}]
        emitted = self.generate([OUT_1], rules, "direct")["route"]["rules"]
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["source_ip_cidr"],
                         ["192.168.1.50/32", "192.168.1.51/32"])

    def test_device_is_resolved_through_its_lease(self):
        # The MAC in the rule carries no address; it comes from the static
        # lease, which is why the lease is mandatory.
        rules = [{"clients": ["00:11:22:33:44:55"], "target": "out_1"}]
        emitted = self.generate(
            [OUT_1], rules, "direct",
            addresses={"00:11:22:33:44:55": "10.0.0.7"})["route"]["rules"]
        self.assertEqual(emitted[0]["source_ip_cidr"], ["10.0.0.7/32"])

    def test_every_rule_names_the_inbound(self):
        rules = [{"clients": ["00:11:22:33:44:55"], "target": "out_1"},
                 {"clients": ["10:20:30:40:50:60"], "target": "block"}]
        config = self.generate([OUT_1], rules, "block")
        for rule in config["route"]["rules"]:
            self.assertEqual(rule["inbound"], ["zarap-tproxy"])

    def test_inbound_is_a_single_tproxy_listener(self):
        inbounds = self.generate([OUT_1], [], "direct")["inbounds"]
        self.assertEqual(len(inbounds), 1)
        self.assertEqual(inbounds[0]["type"], "tproxy")
        self.assertEqual(inbounds[0]["tag"], "zarap-tproxy")
        self.assertEqual(inbounds[0]["listen_port"], 7893)

    def test_outbound_tags_are_validated(self):
        script = "%s\nfor (let tag in %s) printf('%%s ', valid_outbound_tag(tag));\n" % (
            self.prelude,
            json.dumps(["out_1", "out_42", "direct", "block", "dns", "main",
                        "zarap-tproxy", "out_", "proxy", "Out_1", ""]))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(
                done.stdout.split(),
                ["true", "true"] + ["false"] * 9)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
