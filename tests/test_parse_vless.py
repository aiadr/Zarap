"""Runs the real parse_vless from the backend under a ucode interpreter.

The backend is a rpcd plugin, so it cannot be imported directly: it pulls in
fs, ubus, uci and luci.http. The needed functions are lifted out of it and run
against stubs, which keeps the parsing rules under test rather than a copy of
them. Skipped when no ucode interpreter is available; CI builds one.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "luci-app-zarap/root/usr/share/rpcd/ucode/zarap.uc"

UUID = "123e4567-e89b-42d3-a456-426614174000"
PBK = "0123456789abcdefghijklmnopqrstuvwxyzABCDE"
BASE_PARAMS = f"security=reality&sni=cdn.example.test&fp=chrome&pbk={PBK}&type=tcp"

# luci.http is unavailable outside rpcd.
STUBS = """
function urldecode(s) {
	s = replace(s || '', /\\+/g, ' ');
	return replace(s, /%([0-9A-Fa-f]{2})/g, function(m, h) { return chr(hex(h)); });
}
function urldecode_params(q) {
	let out = {};
	for (let pair in split(q || '', '&')) {
		if (!pair) continue;
		let eq = index(pair, '=');
		out[urldecode(eq >= 0 ? substr(pair, 0, eq) : pair)] =
			urldecode(eq >= 0 ? substr(pair, eq + 1) : '');
	}
	return out;
}
"""


def find_ucode():
    return os.environ.get("UCODE_BIN") or shutil.which("ucode") or next(
        (p for p in ("/tmp/ucode/build/ucode",) if Path(p).is_file()), None)


def lift(source, name):
    """Extract one top-level function by brace matching."""
    start = source.index(f"function {name}(")
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise AssertionError(f"unterminated function {name}")


class ParseVlessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ucode = find_ucode()
        if not cls.ucode:
            raise unittest.SkipTest("no ucode interpreter available")
        source = BACKEND.read_text()
        cls.prelude = STUBS + "\n".join(
            lift(source, name) for name in ("result_error", "input_error", "parse_vless"))

    def parse(self, link):
        script = "%s\nprintf('%%J', parse_vless(%s));\n" % (
            self.prelude, json.dumps(link))
        with tempfile.NamedTemporaryFile("w", suffix=".uc", delete=False) as handle:
            handle.write(script)
            path = handle.name
        try:
            done = subprocess.run([self.ucode, path], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            return json.loads(done.stdout)
        finally:
            os.unlink(path)

    def test_accepts_an_empty_path_before_the_query(self):
        # The form most share links use; the slash used to land inside the port.
        result = self.parse(f"vless://{UUID}@proxy.example.test:443/?{BASE_PARAMS}")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["server_port"], 443)
        self.assertEqual(result["config"]["server"], "proxy.example.test")

    def test_accepts_the_canonical_form(self):
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["server_port"], 443)

    def test_accepts_a_path_together_with_a_fragment(self):
        result = self.parse(
            f"vless://{UUID}@proxy.example.test:8443/?{BASE_PARAMS}#My%20Server")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["server_port"], 8443)

    def test_accepts_a_bracketed_ipv6_server(self):
        result = self.parse(f"vless://{UUID}@[2001:db8::1]:443?{BASE_PARAMS}")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["server"], "2001:db8::1")

    def test_accepts_the_vision_flow(self):
        result = self.parse(
            f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}&flow=xtls-rprx-vision")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["flow"], "xtls-rprx-vision")

    def test_survives_invisible_characters_from_a_paste(self):
        # Copying a link out of a chat or a web page brings along a
        # non-breaking space, a zero-width character or a leading BOM; a stray
        # one beside the port made it read as "443 " and the link was rejected.
        for label, intruder in (
            ("space", " "),
            ("non-breaking space", "\u00a0"),
            ("zero-width space", "\u200b"),
            ("tab", "\t"),
        ):
            with self.subTest(label):
                link = (f"vless://{UUID}@proxy.example.test:443{intruder}"
                        f"?{BASE_PARAMS}")
                result = self.parse(link)
                self.assertTrue(result["ok"], f"{label}: {result.get('error')}")
                self.assertEqual(result["config"]["server_port"], 443)

    def test_survives_a_leading_byte_order_mark(self):
        result = self.parse(f"\ufeffvless://{UUID}@proxy.example.test:443?{BASE_PARAMS}")
        self.assertTrue(result["ok"], result.get("error"))

    def test_keeps_the_connection_name_from_the_fragment(self):
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}#My%20Server")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["name"], "My Server")

    def test_keeps_a_name_written_in_another_script(self):
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}#Мой сервер")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["name"], "Мой сервер")

    def test_a_link_without_a_fragment_has_no_name(self):
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}")
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["config"]["name"], "")

    def test_a_name_is_stripped_of_control_characters_and_bounded(self):
        # It goes into uci and back onto the page, so a newline would corrupt
        # the config file and an unbounded string would not belong in either.
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}#one\ntwo")
        self.assertEqual(result["config"]["name"], "onetwo")
        long_name = "x" * 200
        result = self.parse(f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}#{long_name}")
        self.assertEqual(len(result["config"]["name"]), 64)

    def test_rejects_a_port_outside_the_valid_range(self):
        for port in ("0", "70000"):
            result = self.parse(f"vless://{UUID}@proxy.example.test:{port}?{BASE_PARAMS}")
            self.assertFalse(result["ok"])
            self.assertEqual(result["kind"], "input_error")

    def test_rejects_transports_and_securities_outside_the_mvp(self):
        ws = self.parse(
            f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}".replace("type=tcp", "type=ws"))
        self.assertFalse(ws["ok"])
        plain = self.parse(
            f"vless://{UUID}@proxy.example.test:443?{BASE_PARAMS}".replace(
                "security=reality", "security=tls"))
        self.assertFalse(plain["ok"])

    def test_rejects_a_malformed_uuid(self):
        result = self.parse(f"vless://not-a-uuid@proxy.example.test:443?{BASE_PARAMS}")
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
