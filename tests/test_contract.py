import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "luci-app-zarap"
BACKEND = (PACKAGE_ROOT / "root/usr/share/rpcd/ucode/zarap.uc").read_text()
NFT = (PACKAGE_ROOT / "root/etc/nftables.d/90-zarap.nft").read_text()
MAKEFILE = (PACKAGE_ROOT / "Makefile").read_text()


class PackageContractTests(unittest.TestCase):
    def test_repository_has_openwrt_feed_layout(self):
        self.assertFalse((ROOT / "Makefile").exists())
        self.assertTrue((PACKAGE_ROOT / "Makefile").is_file())
        self.assertTrue((PACKAGE_ROOT / "htdocs").is_dir())
        self.assertTrue((PACKAGE_ROOT / "root").is_dir())

    def test_required_package_dependencies_are_declared(self):
        for package in (
            "sing-box",
            "firewall4",
            "kmod-nft-tproxy",
            "kmod-nft-socket",
            "ip-full",
        ):
            self.assertIn(f"+{package}", MAKEFILE)

    def test_json_manifests_are_valid(self):
        for path in (
            PACKAGE_ROOT / "root/usr/share/luci/menu.d/luci-app-zarap.json",
            PACKAGE_ROOT / "root/usr/share/rpcd/acl.d/luci-app-zarap.json",
        ):
            json.loads(path.read_text())

    def test_rpc_namespace_and_update_allowlist(self):
        self.assertIn("return { 'zarap': methods };", BACKEND)
        self.assertIn("'luci-app-zarap': true", BACKEND)
        self.assertIn("'sing-box': true", BACKEND)
        self.assertNotIn("apk upgrade", BACKEND)

    def test_private_mac_detection_covers_locally_administered_bit(self):
        pattern = re.compile(r"^[0-9A-F][2367ABEF]:")
        self.assertRegex("02:00:00:00:00:01", pattern)
        self.assertRegex("A6:00:00:00:00:01", pattern)
        self.assertNotRegex("00:11:22:33:44:55", pattern)

    def test_fixed_tproxy_resources(self):
        for value in ("7893", "0x5a52", "2022", "zarap_clients_v4"):
            self.assertIn(value, BACKEND + NFT)

    def test_kill_switch_covers_ipv4_and_ipv6(self):
        self.assertIn("ip saddr @zarap_clients_v4 reject", NFT)
        self.assertIn("ether saddr @zarap_clients_mac ether type ip6 reject", NFT)

    def test_status_does_not_return_proxy_secrets(self):
        status_body = BACKEND.split("function status()", 1)[1].split("function logs()", 1)[0]
        for secret_field in ("uuid:", "public_key:", "short_id:"):
            self.assertNotIn(secret_field, status_body)


if __name__ == "__main__":
    unittest.main()
