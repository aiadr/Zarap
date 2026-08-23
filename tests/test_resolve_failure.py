"""Runs the real log reading from the backend under a ucode interpreter.

A resolver that does not answer is the one failure that looks like health:
connections are established, the log carries no error the status watches for,
and nothing works. recent_failures is what turns that silence into a sentence,
so it is lifted out of the rpcd plugin and run against stubbed log output.
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

# What sing-box writes at the `info` level the generator sets, when the address
# of the server cannot be resolved. Taken from a real router.
UNRESOLVED = (
    "ERROR [1234 10.0s] connection: open connection to 198.18.0.21:443 using "
    "outbound/vless[out_4]: lookup cdn1.aidar.one: context deadline exceeded"
)
LOOP = (
    "ERROR [1234 4.6s] connection: open connection to 198.18.0.21:443 using "
    "outbound/vless[out_4]: lookup cdn1.aidar.one: DNS query loopback in "
    "transport[dns_out_4]"
)
# The same word at `debug`, both times on a lookup that is not a failure.
DEBUG_OK = (
    "DEBUG [1234 0ms] dns: lookup domain example.com\n"
    "DEBUG [1234 16ms] dns: lookup succeed for example.com: 104.20.23.154"
)
HEALTHY = (
    "INFO [1234 0ms] inbound/tproxy[zarap-tproxy]: inbound connection to 1.2.3.4:443\n"
    "INFO [1234 3ms] outbound/vless[out_3]: outbound connection to 1.2.3.4:443"
)


class ResolveFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        cls.body = lift(BACKEND.read_text(), "recent_failures")

    def scan(self, log):
        script = "function capture(command) { return { code: 0, output: %s }; }\n%s\nprintf('%%J', recent_failures());\n" % (
            json.dumps(log), self.body)
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_a_name_that_did_not_resolve_is_named(self):
        # Без имени сообщение отправляет искать поломку в подключении, тогда
        # как чинится она полем резолвера на той же странице.
        self.assertEqual(self.scan(UNRESOLVED),
                         {"connection": True, "unresolved": "cdn1.aidar.one"})
        self.assertEqual(self.scan(LOOP),
                         {"connection": True, "unresolved": "cdn1.aidar.one"})

    def test_a_successful_lookup_is_not_a_failure(self):
        # На уровне debug слово lookup встречается и в удачном резолве. Отличает
        # их двоеточие сразу за именем, которого там нет.
        self.assertEqual(self.scan(DEBUG_OK),
                         {"connection": False, "unresolved": ""})

    def test_a_quiet_log_is_quiet(self):
        self.assertEqual(self.scan(HEALTHY),
                         {"connection": False, "unresolved": ""})

    def test_other_failures_are_still_caught_but_unnamed(self):
        # Прежние маркеры никуда не делись: они говорят, что что-то не
        # соединяется, но назвать им нечего.
        for line in ("ERROR reality handshake failed",
                     "ERROR dial tcp 1.2.3.4:443: connection refused",
                     "ERROR write: network is unreachable"):
            self.assertEqual(self.scan(line),
                             {"connection": True, "unresolved": ""}, line)

    def test_the_unresolved_name_wins_over_a_generic_marker(self):
        # i/o timeout стоит и в самой строке про резолв: без приоритета
        # сообщение снова стало бы безымянным.
        self.assertEqual(
            self.scan(UNRESOLVED.replace("context deadline exceeded", "i/o timeout")),
            {"connection": True, "unresolved": "cdn1.aidar.one"})


if __name__ == "__main__":
    unittest.main()
