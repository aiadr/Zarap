"""Runs the real dnsmasq reconfiguration from the backend under ucode.

The mode that hands the household's DNS to sing-box takes three keys away from
dnsmasq, and the whole reason it is acceptable is that it gives them back —
when Zarap is switched off, not only when the package is removed. That is the
part worth testing, because nobody notices a backup until it fails to restore.
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

# Крошечный uci в памяти: хранит значения и умеет списки, больше от него
# ничего не требуется.
STUB = """
let store = %s;
function key(config, section, option) { return config + '.' + section + '.' + option; }
let uci = {
	get: function(config, section, option) {
		let value = store[key(config, section, option)];
		return value == null ? null : value;
	},
	set: function(config, section, option, value) { store[key(config, section, option)] = value; },
	delete: function(config, section, option) { delete store[key(config, section, option)]; },
	foreach: function(config, type, fn) { fn({ '.name': 'cfg01' }); }
};
function dnsmasq_section() { return 'cfg01'; }
"""


class DnsmasqTakeoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        constants = "\n".join(
            line for line in source.splitlines()
            if line.startswith(("const DNS_PORT", "const DNS_FORWARD", "const DNS_TAKEOVER")))
        cls.prelude = constants + "\n" + "\n".join(lift(source, name) for name in (
            "dns_routes", "dnsmasq_take_over", "dnsmasq_hand_back", "configure_dnsmasq"))

    def run_uci(self, store, rules, enabled, resolve_all):
        script = "%s\n%s\nconfigure_dnsmasq(uci, %s, %s, %s);\nprintf('%%J', store);\n" % (
            STUB % json.dumps(store), self.prelude, json.dumps(rules),
            "true" if enabled else "false", "true" if resolve_all else "false")
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_it_remembers_what_it_took_and_gives_it_back(self):
        # Полный круг: чужие настройки, включение, выключение. То, что вернулось,
        # обязано совпасть с тем, что было, — иначе домашний DNS остаётся нашим
        # после того, как нас выключили.
        before = {
            "dhcp.cfg01.server": ["77.88.8.8", "77.88.8.1"],
            "dhcp.cfg01.cachesize": "1000",
        }
        taken = self.run_uci(dict(before), [], True, True)
        self.assertEqual(taken["dhcp.cfg01.server"], ["127.0.0.1#5353"])
        self.assertEqual(taken["dhcp.cfg01.noresolv"], "1")
        self.assertEqual(taken["dhcp.cfg01.cachesize"], "0")
        self.assertEqual(taken["zarap.main.saved_dns_server"], ["77.88.8.8", "77.88.8.1"])
        self.assertEqual(taken["zarap.main.saved_dns_cachesize"], "1000")
        # noresolv не было — запоминается пустым, чтобы возврат его удалил.
        self.assertEqual(taken["zarap.main.saved_dns_noresolv"], "")

        back = self.run_uci(dict(taken), [], False, True)
        self.assertEqual(back["dhcp.cfg01.server"], before["dhcp.cfg01.server"])
        self.assertEqual(back["dhcp.cfg01.cachesize"], before["dhcp.cfg01.cachesize"])
        self.assertNotIn("dhcp.cfg01.noresolv", back)
        # Запомненное убирается: иначе следующее выключение вернуло бы протухшее.
        for key in ("server", "noresolv", "cachesize"):
            self.assertNotIn("zarap.main.saved_dns_" + key, back)

    def test_applying_twice_does_not_remember_our_own_values(self):
        # Иначе второе применение запишет в «прежние настройки» наши, и вернуть
        # пользователю будет уже нечего.
        once = self.run_uci({"dhcp.cfg01.server": ["8.8.8.8"]}, [], True, True)
        twice = self.run_uci(dict(once), [], True, True)
        self.assertEqual(twice["zarap.main.saved_dns_server"], ["8.8.8.8"])

    def test_switching_zarap_off_hands_dns_back(self):
        # sing-box остановлен, и пересылка на него оставила бы дом без имён.
        taken = self.run_uci({"dhcp.cfg01.server": ["8.8.8.8"]}, [], True, True)
        off = self.run_uci(dict(taken), [], False, True)
        self.assertEqual(off["dhcp.cfg01.server"], ["8.8.8.8"])

    def test_without_the_mode_only_the_named_domains_are_forwarded(self):
        # Прежнее поведение: чужие строки на месте, свои — адресные.
        rules = [{"domains": ["youtube.com"], "target": "out_1"}]
        result = self.run_uci({"dhcp.cfg01.server": ["8.8.8.8"]}, rules, True, False)
        self.assertEqual(result["dhcp.cfg01.server"],
                         ["8.8.8.8", "/youtube.com/127.0.0.1#5353"])
        self.assertNotIn("dhcp.cfg01.noresolv", result)


if __name__ == "__main__":
    unittest.main()
