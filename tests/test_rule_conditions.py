"""Runs the real rule validation from the backend under a ucode interpreter.

validate_rules is what stands between a hand-edited request and the generator,
so the rules it enforces are lifted out of the rpcd plugin and executed rather
than restated here. Skipped when no ucode interpreter is available; CI builds
one.
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

TV = "00:11:22:33:44:55"
TABLET = "10:20:30:40:50:60"


class RuleConditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        cls.prelude = "\n".join(lift(source, name) for name in (
            "result_error", "input_error", "normalize_mac", "is_private_mac",
            "valid_ipv4", "normalize_domain", "normalize_cidr", "normalize_port",
            "valid_target", "valid_ruleset_tag", "validate_rulesets",
            "validate_rule_list", "validate_rules", "startup_hint"))

    def validate(self, rules, tags=None, declared=None):
        script = "%s\nprintf('%%J', validate_rules(%s, %s, %s));\n" % (
            self.prelude, json.dumps(rules),
            json.dumps({"out_1": True} if tags is None else tags),
            json.dumps(declared or {}))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def refusal(self, rules):
        result = self.validate(rules)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["kind"], "input_error")
        return result["error"]

    def accepted(self, rule):
        result = self.validate([rule])
        self.assertTrue(result["ok"], result)
        return result["rules"][0]

    def test_a_rule_needs_at_least_one_condition(self):
        # The "everything else" role belongs to main.final; a rule without a
        # condition would be a second, silent copy of it.
        self.assertIn("хотя бы одно условие", self.refusal([{"target": "out_1"}]))

    def test_any_single_condition_is_enough(self):
        for rule in ({"clients": [TV]}, {"domains": ["example.com"]},
                     {"ip_cidr": ["10.0.0.0/8"]},
                     {"ports": ["443"]}, {"network": "udp"}):
            self.assertTrue(self.validate([dict(rule, target="out_1")])["ok"], rule)

    def test_a_domain_is_kept_as_written_and_lowercased(self):
        rule = self.accepted({"domains": ["YouTube.com", ".googlevideo.com"],
                              "target": "out_1"})
        self.assertEqual(rule["domains"], ["youtube.com", ".googlevideo.com"])

    def test_a_domain_with_a_scheme_or_a_path_is_refused(self):
        # The generator would put it straight into the configuration, where it
        # would match nothing and say nothing.
        self.assertIn("без схемы", self.refusal(
            [{"domains": ["https://youtube.com"], "target": "out_1"}]))
        self.assertIn("без схемы", self.refusal(
            [{"domains": ["youtube.com/watch"], "target": "out_1"}]))

    def test_a_star_is_refused_with_what_to_write_instead(self):
        # "*.example.com" is the shape people reach for, and the entry already
        # covers subdomains, so the refusal has to say that rather than just no.
        message = self.refusal([{"domains": ["*.example.com"], "target": "out_1"}])
        self.assertIn("Звёздочка", message)
        self.assertIn("точки", message)

    def test_a_cyrillic_domain_is_refused_asking_for_punycode(self):
        # There is nothing on the router to convert it with.
        self.assertIn("punycode", self.refusal(
            [{"domains": ["сайт.рф"], "target": "out_1"}]))

    def test_something_that_is_not_a_domain_is_refused(self):
        for value in ("youtube", "", ".", "youtube..com", "you tube.com"):
            self.refusal([{"domains": [value], "target": "out_1"}])

    def test_a_bare_address_becomes_its_own_range(self):
        self.assertEqual(
            self.accepted({"ip_cidr": ["93.184.216.34"], "target": "out_1"})["ip_cidr"],
            ["93.184.216.34/32"])

    def test_a_mask_is_kept_and_bounded(self):
        self.assertEqual(
            self.accepted({"ip_cidr": ["10.0.0.0/8"], "target": "out_1"})["ip_cidr"],
            ["10.0.0.0/8"])
        self.assertIn("маска", self.refusal(
            [{"ip_cidr": ["10.0.0.0/33"], "target": "out_1"}]))

    def test_ipv6_is_refused_by_name(self):
        # It is neither routed nor handed out, so an entry for it would sit in
        # the configuration doing nothing. Saying so beats "некорректный".
        self.assertIn("IPv6", self.refusal(
            [{"ip_cidr": ["2001:db8::/32"], "target": "out_1"}]))

    def test_a_range_that_is_not_a_range_is_refused(self):
        for value in ("10.0.0.256/8", "10.0.0.0/8/8", "", "example.com"):
            self.refusal([{"ip_cidr": [value], "target": "out_1"}])

    def test_ports_keep_their_form(self):
        rule = self.accepted({"ports": ["443", "1000:2000"], "target": "out_1"})
        self.assertEqual(rule["ports"], ["443", "1000:2000"])

    def test_ports_are_bounded_and_ordered(self):
        for value in ("0", "65536", "-1", "443x", ""):
            self.refusal([{"ports": [value], "target": "out_1"}])
        self.assertIn("начало больше конца", self.refusal(
            [{"ports": ["2000:1000"], "target": "out_1"}]))

    def test_only_tcp_and_udp_are_protocols(self):
        self.assertEqual(
            self.accepted({"network": "UDP", "target": "out_1"})["network"], "udp")
        self.assertIn("tcp или udp", self.refusal(
            [{"network": "icmp", "target": "out_1"}]))

    def test_a_repeat_inside_one_rule_is_refused(self):
        # Two identical entries mean one of them was meant to be something else.
        self.assertIn("дважды", self.refusal(
            [{"ip_cidr": ["10.0.0.0/8", "10.0.0.0/8"], "target": "out_1"}]))
        self.assertIn("дважды", self.refusal(
            [{"ports": ["443", "443"], "target": "out_1"}]))

    def test_the_same_range_in_two_rules_is_allowed(self):
        # Overlapping rules are legitimate: the first match wins, and the page
        # shows the order that decides it.
        self.assertTrue(self.validate([
            {"ip_cidr": ["10.0.0.0/8"], "target": "out_1"},
            {"ip_cidr": ["10.0.0.0/8"], "target": "block"},
        ])["ok"])

    def test_conditions_do_not_loosen_the_checks_on_devices(self):
        # A destination condition is not a way around the private-MAC refusal:
        # the lease is what the rule rests on either way.
        self.assertIn("приватный MAC", self.refusal(
            [{"clients": ["02:11:22:33:44:55"], "ip_cidr": ["10.0.0.0/8"],
              "target": "out_1"}]))

    def test_a_missing_list_is_an_empty_one(self):
        rule = self.accepted({"clients": [TV], "target": "out_1"})
        self.assertEqual(rule["domains"], [])
        self.assertEqual(rule["ip_cidr"], [])
        self.assertEqual(rule["ports"], [])
        self.assertEqual(rule["network"], "")

    def test_a_list_of_the_wrong_type_is_refused(self):
        self.assertIn("неверный формат", self.refusal(
            [{"ip_cidr": "10.0.0.0/8", "target": "out_1"}]))

    def test_the_target_is_still_checked(self):
        self.assertIn("несуществующее подключение", self.refusal(
            [{"ip_cidr": ["10.0.0.0/8"], "target": "out_9"}]))
        for target in ("direct", "block", "out_1"):
            self.assertTrue(
                self.validate([{"clients": [TABLET], "target": target}])["ok"])

    def rulesets(self, entries, tags=None):
        script = "%s\nprintf('%%J', validate_rulesets(%s, %s));\n" % (
            self.prelude, json.dumps(entries),
            json.dumps({"out_1": True} if tags is None else tags))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_a_ruleset_needs_a_name_an_address_and_a_reachable_detour(self):
        good = self.rulesets([{"tag": "rs_1", "label": "Реклама",
                               "url": "https://example.org/a.srs",
                               "detour": "out_1", "update_interval": "1d"}])
        self.assertTrue(good["ok"], good)
        self.assertEqual(good["rulesets"][0]["detour"], "out_1")

        self.assertIn("Некорректное имя", self.rulesets(
            [{"tag": "ads", "url": "https://example.org/a.srs"}])["error"])
        self.assertIn("http", self.rulesets(
            [{"tag": "rs_1", "url": "example.org/a.srs"}])["error"])
        self.assertIn("несуществующее подключение", self.rulesets(
            [{"tag": "rs_1", "url": "https://example.org/a.srs",
              "detour": "out_9"}])["error"])
        self.assertIn("12h", self.rulesets(
            [{"tag": "rs_1", "url": "https://example.org/a.srs",
              "update_interval": "каждый день"}])["error"])

    def test_a_rule_points_only_at_a_declared_set(self):
        # The section list and the rules are submitted together, so a reference
        # to a set nobody declared is an error the request can be refused for.
        self.assertIn("несуществующий набор", self.validate(
            [{"rule_sets": ["rs_1"], "target": "out_1"}])["error"])
        self.assertTrue(self.validate(
            [{"rule_sets": ["rs_1"], "target": "out_1"}],
            declared={"rs_1": True})["ok"])

    def hint(self, rulesets):
        script = "%s\nprintf('%%s', startup_hint(%s));\n" % (
            self.prelude, json.dumps(rulesets))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout
        finally:
            os.unlink(path)

    def test_a_failed_start_names_the_rule_sets_as_a_suspect(self):
        # Until a list reaches the cache, starting depends on somebody else's
        # server, and a bare "could not start Zarap" sends the reader to the
        # proxy settings instead.
        message = self.hint([{"tag": "rs_1", "label": "Реклама"}])
        self.assertIn("Реклама (rs_1)", message)
        self.assertIn("журнале", message)

    def test_without_rule_sets_the_failure_says_nothing_about_them(self):
        self.assertEqual(self.hint([]), "")

    def test_the_order_of_the_rules_is_kept(self):
        result = self.validate([
            {"clients": [TV], "target": "out_1"},
            {"ports": ["443"], "target": "block"},
        ])
        self.assertEqual([rule["target"] for rule in result["rules"]],
                         ["out_1", "block"])


if __name__ == "__main__":
    unittest.main()
