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
            ("valid_outbound_tag", "outbound_json", "rule_jsons", "sing_box_config"))

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

    def resolve(self, rules, final, macs):
        source = BACKEND.read_text()
        script = "%s\n%s\nfor (let mac in %s) printf('%%s ', device_routing(mac, %s, %s).target);\n" % (
            "\n".join(lift(source, name) for name in
                      ("guarded_macs", "conditional_rule", "device_routing")),
            "", json.dumps(macs), json.dumps(rules), json.dumps(final))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout.split()
        finally:
            os.unlink(path)

    def test_source_range_and_port_meet_in_one_element(self):
        # Source, destination and qualifiers are anded, which is what sing-box
        # does with the fields of a single rule anyway. The second element of a
        # group appears only once a second kind of destination exists, so there
        # is one element here and nothing to say about adjacency yet.
        rules = [{"clients": ["00:11:22:33:44:55"], "ip_cidr": ["149.154.160.0/20"],
                  "ports": ["443"], "target": "out_1"}]
        emitted = self.generate([OUT_1], rules, "direct")["route"]["rules"]
        self.assertEqual(len(emitted), 1)
        self.assertEqual(emitted[0]["ip_cidr"], ["149.154.160.0/20"])
        self.assertEqual(emitted[0]["source_ip_cidr"], ["192.168.1.50/32"])
        self.assertEqual(emitted[0]["port"], [443])
        self.assertEqual(emitted[0]["outbound"], "out_1")

    def test_ports_and_ranges_land_in_their_own_fields(self):
        rules = [{"clients": [], "ports": ["443", "1000:2000"], "network": "udp",
                  "target": "block"}]
        emitted = self.generate([OUT_1], rules, "direct")["route"]["rules"]
        self.assertEqual(emitted[0]["port"], [443])
        self.assertEqual(emitted[0]["port_range"], ["1000:2000"])
        self.assertEqual(emitted[0]["network"], ["udp"])
        self.assertEqual(emitted[0]["action"], "reject")

    def test_a_rule_without_devices_carries_no_source(self):
        # An empty array would read as "from nowhere" rather than "from anyone".
        rules = [{"clients": [], "ip_cidr": ["10.0.0.0/8"], "target": "direct"}]
        emitted = self.generate([OUT_1], rules, "out_1")["route"]["rules"]
        self.assertNotIn("source_ip_cidr", emitted[0])

    def test_an_unresolvable_device_leaves_the_rule_without_a_source(self):
        # The lease is what turns a MAC into an address. Without one there is
        # nothing to match on, and the rule must not silently widen to everyone
        # — that case is refused before generation, in validate_request.
        rules = [{"clients": ["FF:FF:FF:FF:FF:FF"], "ip_cidr": ["10.0.0.0/8"],
                  "target": "out_1"}]
        emitted = self.generate([OUT_1], rules, "direct")["route"]["rules"]
        self.assertNotIn("source_ip_cidr", emitted[0])

    def test_first_matching_rule_decides_where_a_device_goes(self):
        rules = [
            {"clients": ["00:11:22:33:44:55"], "target": "out_1"},
            {"clients": ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"], "target": "block"},
        ]
        self.assertEqual(
            self.resolve(rules, "direct",
                         ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "10:20:30:40:50:60"]),
            ["out_1", "block", "direct"])

    def routing(self, rules, final, mac):
        source = BACKEND.read_text()
        script = "%s\nprintf('%%J', device_routing(%s, %s, %s));\n" % (
            "\n".join(lift(source, name)
                      for name in ("conditional_rule", "device_routing")),
            json.dumps(mac), json.dumps(rules), json.dumps(final))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_a_conditional_rule_does_not_decide_where_a_device_goes(self):
        # It speaks about part of the traffic, so it is listed rather than
        # answered with: the device still falls through to the remainder.
        rules = [{"clients": ["00:11:22:33:44:55"], "ip_cidr": ["10.0.0.0/8"],
                  "target": "out_1"}]
        self.assertEqual(self.routing(rules, "direct", "00:11:22:33:44:55"),
                         {"target": "direct", "partial": [1]})

    def test_a_rule_naming_no_device_is_partial_for_everyone(self):
        rules = [{"clients": [], "ports": ["443"], "network": "udp", "target": "block"}]
        self.assertEqual(self.routing(rules, "out_1", "00:11:22:33:44:55"),
                         {"target": "out_1", "partial": [1]})

    def test_collecting_partial_rules_stops_at_the_rule_that_takes_it_whole(self):
        # Anything after the rule that catches the device unconditionally never
        # sees its traffic, so listing it would send the reader hunting.
        rules = [
            {"clients": ["00:11:22:33:44:55"], "ports": ["443"], "target": "out_1"},
            {"clients": ["00:11:22:33:44:55"], "target": "block"},
            {"clients": ["00:11:22:33:44:55"], "ip_cidr": ["10.0.0.0/8"], "target": "out_1"},
        ]
        self.assertEqual(self.routing(rules, "direct", "00:11:22:33:44:55"),
                         {"target": "block", "partial": [1]})

    def test_guarded_macs_collects_every_named_device(self):
        source = BACKEND.read_text()
        rules = [
            {"clients": ["00:11:22:33:44:55"], "target": "direct"},
            {"clients": ["AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"], "target": "block"},
        ]
        # Iterating an object in ucode yields keys, and the set has to come out
        # deduplicated regardless of what the rules target.
        script = "%s\nlet macs = [];\nfor (let mac in guarded_macs(%s)) push(macs, mac);\nprintf('%%J', sort(macs));\n" % (
            lift(source, "guarded_macs"), json.dumps(rules))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout),
                             ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"])
        finally:
            os.unlink(path)

    def guarded(self, rules):
        source = BACKEND.read_text()
        script = "%s\nlet macs = [];\nfor (let mac in guarded_macs(%s)) push(macs, mac);\nprintf('%%J', sort(macs));\n" % (
            lift(source, "guarded_macs"), json.dumps(rules))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_a_rule_limited_by_destination_still_guards_its_device(self):
        """Invariant 6: the guarantee is a property of the device, not a flow.

        Otherwise switching Zarap off would hand the device a direct path to
        the WAN for exactly the connections its rule was written about.
        """
        rules = [{"clients": ["00:11:22:33:44:55"], "ip_cidr": ["10.0.0.0/8"],
                  "ports": ["443"], "target": "out_1"}]
        self.assertEqual(self.guarded(rules), ["00:11:22:33:44:55"])

    def test_a_rule_naming_no_device_guards_nobody(self):
        """Invariant 7: a destination condition names no device.

        It routes while Zarap runs and leaves no trace when it is switched off,
        which is the same thing main.final does.
        """
        rules = [{"clients": [], "ip_cidr": ["10.0.0.0/8"], "target": "out_1"},
                 {"clients": [], "ports": ["443"], "network": "udp", "target": "block"}]
        self.assertEqual(self.guarded(rules), [])

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
