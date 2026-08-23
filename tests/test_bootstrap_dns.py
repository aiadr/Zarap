"""Runs the real bootstrap-resolver parsing from the backend under ucode.

The resolver for the server's own address is the one DNS setting Zarap has, and
what the user types there decides whether the query leaves the router encrypted,
in the clear, or at all. parse_bootstrap is lifted out of the rpcd plugin and
executed rather than restated here. Skipped when no ucode interpreter is
available; CI builds one.
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


class BootstrapDnsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        constants = "\n".join(
            line for line in source.splitlines()
            if line.startswith(("const DNS_UPSTREAM", "const BOOTSTRAP_TAG",
                                "const BOOTSTRAP_DEFAULT", "const BOOTSTRAP_SCHEMES",
                                "const TUNNEL_DEFAULT")))
        cls.prelude = constants + "\n" + "\n".join(lift(source, name) for name in (
            "result_error", "input_error", "valid_ipv4", "parse_resolver",
            "parse_bootstrap", "parse_tunnel_dns"))

    def parse(self, value):
        script = "%s\nprintf('%%J', parse_bootstrap(%s));\n" % (
            self.prelude, json.dumps(value))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_an_empty_setting_falls_back_to_the_router_itself(self):
        # Умолчание — резолвер самого роутера. DoH к 1.1.1.1, стоявший здесь
        # раньше, оказался умолчанием, которое не работает ровно там, ради чего
        # пакет и написан, а его отказ выглядит как тишина.
        for value in ("", "   ", None):
            parsed = self.parse(value)
            self.assertTrue(parsed["ok"])
            self.assertEqual(parsed["value"], "local")
            self.assertEqual(parsed["server"],
                             {"type": "local", "tag": "dns_bootstrap"})

    def test_the_scheme_decides_what_leaves_the_router(self):
        # This is the whole point of the setting: https and tls encrypt the
        # query, udp and tcp do not — and the plain ones are what get through
        # where DoH is blocked.
        for value, expected in (
            ("https://1.1.1.1", "https"),
            ("tls://9.9.9.9", "tls"),
            ("udp://8.8.8.8", "udp"),
            ("tcp://8.8.4.4", "tcp"),
        ):
            parsed = self.parse(value)
            self.assertTrue(parsed["ok"], value)
            self.assertEqual(parsed["server"]["type"], expected)
            self.assertEqual(parsed["value"], value)
            # Никакого detour: сервер без него дозванивается напрямую, а
            # `detour: "direct"` sing-box отвергает.
            self.assertNotIn("detour", parsed["server"])

    def test_a_bare_address_is_a_plain_query(self):
        # Nobody types a scheme when they mean "just use this resolver", and
        # plain DNS is the form that works everywhere.
        parsed = self.parse("192.168.1.1")
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["server"],
                         {"type": "udp", "tag": "dns_bootstrap", "server": "192.168.1.1"})
        self.assertEqual(parsed["value"], "udp://192.168.1.1")

    def test_the_router_can_be_asked_to_resolve_it_itself(self):
        for value in ("local", "LOCAL"):
            parsed = self.parse(value)
            self.assertTrue(parsed["ok"], value)
            self.assertEqual(parsed["value"], "local")
            # Адреса у local нет — резолвер берётся из /etc/resolv.conf, — а
            # тег есть: на него ссылается route.default_domain_resolver.
            self.assertEqual(parsed["server"], {"type": "local", "tag": "dns_bootstrap"})

    def test_a_port_is_carried_and_bounded(self):
        parsed = self.parse("udp://192.168.1.1:5353")
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["server"]["server_port"], 5353)
        self.assertEqual(parsed["value"], "udp://192.168.1.1:5353")
        for value in ("udp://8.8.8.8:0", "udp://8.8.8.8:65536", "udp://8.8.8.8:dns"):
            self.assertEqual(self.parse(value).get("kind"), "input_error", value)

    def test_a_doh_path_is_kept_and_refused_elsewhere(self):
        parsed = self.parse("https://1.1.1.1/dns-query")
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["server"]["path"], "/dns-query")
        # Голый слэш — это не путь, а хвост скопированной ссылки.
        self.assertNotIn("path", self.parse("https://1.1.1.1/")["server"])
        # Остальным схемам путь девать некуда, и промолчать о нём значило бы
        # принять адрес, которым пользователь не пользуется.
        self.assertEqual(self.parse("udp://8.8.8.8/dns-query").get("kind"), "input_error")

    def test_a_name_is_refused_because_it_would_need_this_very_resolver(self):
        # sing-box отказывается стартовать с DNS-сервером, заданным именем:
        # "missing domain resolver for domain server address".
        parsed = self.parse("https://cloudflare-dns.com")
        self.assertEqual(parsed.get("kind"), "input_error")
        self.assertIn("имя", parsed["error"])
        # Отказ обязан назвать форму, которой имя всё-таки записывается.
        self.assertIn("адрес#имя", parsed["error"])

    def test_an_encrypted_resolver_can_be_dialled_by_address_and_checked_by_name(self):
        # DoT и DoH по голому адресу проверяются только там, где в сертификате
        # есть IP SAN. Он есть у Cloudflare и далеко не у всех остальных, и без
        # этой формы такой резолвер просто нельзя было бы назвать.
        parsed = self.parse("tls://77.88.8.8#common.dot.dns.yandex.net")
        self.assertTrue(parsed["ok"], parsed.get("error"))
        # enabled обязателен: без него блок принимается check и молча
        # игнорируется на запуске, а проверка идёт по адресу.
        self.assertEqual(parsed["server"], {
            "type": "tls", "tag": "dns_bootstrap", "server": "77.88.8.8",
            "tls": {"enabled": True, "server_name": "common.dot.dns.yandex.net"}})
        self.assertEqual(parsed["value"], "tls://77.88.8.8#common.dot.dns.yandex.net")

        # Порт и путь никуда не деваются от того, что появилось имя.
        doh = self.parse("https://77.88.8.8:8443/dns-query#common.dns.yandex.net")
        self.assertTrue(doh["ok"], doh.get("error"))
        self.assertEqual(doh["server"]["server_port"], 8443)
        self.assertEqual(doh["server"]["path"], "/dns-query")
        self.assertEqual(doh["server"]["tls"]["server_name"], "common.dns.yandex.net")

    def test_a_certificate_name_makes_no_sense_without_encryption(self):
        # Открытый запрос ничего не проверяет, и принять здесь имя значило бы
        # пообещать проверку, которой не будет.
        for value in ("udp://77.88.8.8#dns.yandex.net", "tcp://77.88.8.8#dns.yandex.net"):
            parsed = self.parse(value)
            self.assertEqual(parsed.get("kind"), "input_error", value)
        self.assertEqual(self.parse("tls://77.88.8.8#не имя").get("kind"), "input_error")

    def test_ipv6_and_unknown_schemes_are_named_in_the_refusal(self):
        self.assertEqual(self.parse("udp://[2606:4700:4700::1111]").get("kind"),
                         "input_error")
        unknown = self.parse("quic://1.1.1.1")
        self.assertEqual(unknown.get("kind"), "input_error")
        self.assertIn("quic", unknown["error"])


    def test_the_tunnel_resolver_is_its_own_setting(self):
        # Раньше он стоял константой с доводом «через туннель выбор ничего не
        # решает». Довод — утверждение о чужой сети: у провайдера сервера
        # Cloudflare может быть закрыт так же, как у своего.
        script = "%s\nprintf('%%J', parse_tunnel_dns(%s));\n"
        def parse_tunnel(value):
            import subprocess, tempfile, os, json as j
            with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
                handle.write(script % (self.prelude, j.dumps(value)))
                path = handle.name
            try:
                done = subprocess.run([self.ucode, path], capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stderr)
                return j.loads(done.stdout)
            finally:
                os.unlink(path)

        # Умолчание — то, что стояло константой.
        self.assertEqual(parse_tunnel("")["value"], "https://1.1.1.1")
        # Тег и detour ставит вызывающий: сервер свой на каждое подключение.
        self.assertEqual(parse_tunnel("")["server"],
                         {"type": "https", "server": "1.1.1.1"})
        self.assertEqual(parse_tunnel("tls://9.9.9.9")["server"]["type"], "tls")
        # `local` здесь бессмыслен: он читает resolv.conf роутера, а спрашивают
        # его через туннель.
        refused = parse_tunnel("local")
        self.assertEqual(refused.get("kind"), "input_error")
        self.assertIn("local", refused["error"])


if __name__ == "__main__":
    unittest.main()
