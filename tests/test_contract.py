import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "luci-app-zarap"
BACKEND = (PACKAGE_ROOT / "root/usr/share/rpcd/ucode/zarap.uc").read_text()
NFT = (PACKAGE_ROOT / "root/etc/nftables.d/90-zarap.nft").read_text()
MAKEFILE = (PACKAGE_ROOT / "Makefile").read_text()
UCI_DEFAULTS = (PACKAGE_ROOT / "root/etc/uci-defaults/90-zarap").read_text()


class PackageContractTests(unittest.TestCase):
    def test_repository_has_openwrt_feed_layout(self):
        self.assertFalse((ROOT / "Makefile").exists())
        self.assertTrue((PACKAGE_ROOT / "Makefile").is_file())
        self.assertTrue((PACKAGE_ROOT / "htdocs").is_dir())
        self.assertTrue((PACKAGE_ROOT / "root").is_dir())

    def test_required_package_dependencies_are_declared(self):
        for package in (
            "firewall4",
            "kmod-nft-tproxy",
            "kmod-nft-socket",
            "ip-full",
            "ss",
        ):
            self.assertIn(f"+{package}", MAKEFILE)

        self.assertRegex(MAKEFILE, r"LUCI_DEPENDS:=.*\bsing-box\b")
        self.assertNotIn("+sing-box", MAKEFILE)
        self.assertNotIn("rpcd-mod-iwinfo", MAKEFILE)

    def test_external_binaries_use_their_installed_paths(self):
        # OpenWrt installs apk as /usr/bin/apk; /sbin/apk does not exist, and
        # calling it silently fails every update check.
        self.assertNotIn("/sbin/apk", BACKEND)
        for path in ("/usr/bin/apk", "/usr/sbin/ss", "/usr/sbin/nft", "/usr/bin/sing-box"):
            self.assertIn(path, BACKEND)

    def test_install_parks_only_the_default_sing_box(self):
        # The package default is parked through the same uci flag apply sets,
        # so applying a configuration hands the service back automatically.
        self.assertIn("uci -q set sing-box.main.enabled='0'", UCI_DEFAULTS)
        self.assertIn("/etc/sing-box/config.json", UCI_DEFAULTS)
        self.assertIn('"$singbox_conf" != "$zarap_conf"', UCI_DEFAULTS)
        self.assertNotIn("sing-box disable", UCI_DEFAULTS)
        self.assertIn("uci.set('sing-box', 'main', 'enabled', enabled ? '1' : '0')", BACKEND)

    def test_status_separates_an_unmanaged_sing_box(self):
        self.assertIn("function unmanaged_sing_box()", BACKEND)
        self.assertIn("не под управлением Zarap", BACKEND)

    def test_installed_version_is_read_from_a_listing(self):
        # apk 3's `info -v` prints description lines, never a version, so the
        # installed version has to be parsed out of `list -I`.
        self.assertNotIn("apk info -v", BACKEND)
        self.assertIn("/usr/bin/apk list -I ", BACKEND)

    def test_external_commands_use_absolute_paths(self):
        # A bare applet name is not guaranteed to exist — BusyBox builds leave
        # applets out, which is how a `timeout` wrapper broke the update check.
        # This only checks the leading command, not ones inside a pipeline.
        commands = re.findall(r"(?:capture|system)\(\s*\[?\s*'([^']+)'", BACKEND)
        self.assertTrue(commands)
        for command in commands:
            leading = command.lstrip("( \t")
            self.assertTrue(leading.startswith("/"), f"not an absolute path: {command}")

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

    def test_rpc_surface_matches_specification(self):
        methods_body = BACKEND.split("const methods = {", 1)[1]
        for method in (
            "status", "validate", "apply", "restart", "stop", "logs",
            "updates", "update_component",
        ):
            self.assertRegex(methods_body, rf"\b{method}:\s*{{")
        self.assertNotRegex(methods_body, r"\bdevices:\s*{")

    def test_rpc_args_declare_types_by_sample_value(self):
        # rpcd builds the ubus policy from the type of each args value, so a
        # type name such as 'bool' declares a string and makes the real call
        # fail with UBUS_STATUS_INVALID_ARGUMENT.
        methods_body = BACKEND.split("const methods = {", 1)[1]
        for type_name in ("'bool'", "'string'", "'number'", "'array'", "'boolean'"):
            self.assertNotIn(type_name, methods_body)
        self.assertIn("args: { refresh: true }", methods_body)
        self.assertIn("args: { link: '', enabled: true, clients: [] }", methods_body)

    def test_atomic_temporary_files_share_target_directories(self):
        self.assertIn("const CONFIG_TMP = '/etc/zarap/.sing-box.json.tmp'", BACKEND)
        self.assertIn("const NFT_TMP = '/etc/nftables.d/.90-zarap.nft.tmp'", BACKEND)
        self.assertIn("const UCI_CANDIDATE = '/etc/config/.zarap-candidate'", BACKEND)
        self.assertIn("cursor(UCI_CANDIDATE, UCI_CANDIDATE_DELTA)", BACKEND)
        self.assertIn("activate_uci_candidate()", BACKEND)

    def test_apply_and_updates_verify_complete_runtime(self):
        for check in ("running && listener && firewall && rule && route",
                      "check_runtime(enabled)", "check_runtime(enabled, LISTENER_WAIT)",
                      "check_runtime(true, LISTENER_WAIT)"):
            self.assertIn(check, BACKEND)
        # Everything that has just restarted the service must wait for the
        # port; only the status view may look without waiting.
        self.assertNotIn("check_runtime(true)", BACKEND)
        self.assertIn("restore_update_files(backups", BACKEND)
        self.assertIn("apk не смог обновить", BACKEND)
        self.assertIn("restore_update_files(backups, true)", BACKEND)

    def test_apply_drives_and_verifies_the_live_firewall_sets(self):
        # A reload leaves existing set contents alone, so apply must flush and
        # repopulate them and then read back what the kernel actually holds.
        self.assertIn("function sync_live_sets(", BACKEND)
        self.assertIn("function live_clients_match(", BACKEND)
        self.assertIn("nft flush set inet fw4 ", BACKEND)
        self.assertIn("!sync_live_sets(live_clients) || !live_clients_match(live_clients)", BACKEND)
        # The rollback path has to converge the kernel too.
        self.assertIn("sync_live_sets(read_clients())", BACKEND)

    def test_the_kill_switch_outlives_the_master_switch(self):
        # A selected device must not reach the WAN directly just because the
        # proxy was switched off; only deselecting it opens that path. The
        # TProxy redirect is the part tied to the proxy running, since sending
        # traffic to a dead port would swallow it instead of rejecting it.
        self.assertIn("validate_candidate(parsed_result.config, client_result.clients, enabled)", BACKEND)
        self.assertIn("let live_clients = client_result.clients;", BACKEND)
        self.assertIn("if (proxying)", BACKEND)
        self.assertNotIn("enabled ? client_result.clients : []", BACKEND)
        view = (PACKAGE_ROOT / "htdocs/luci-static/resources/view/zarap/overview.js").read_text()
        self.assertIn("device.kill_switch = !!(status.firewall && device.selected)", view)

    def test_deselecting_a_device_releases_its_managed_lease(self):
        # zarap_managed was written and read but never acted on, so a static
        # lease outlived the selection that created it with no way to clear it.
        self.assertIn("uci.delete('dhcp', section)", BACKEND)
        self.assertIn("section.zarap_managed == '1' && !selected[", BACKEND)

    def test_device_discovery_uses_hostapd_and_dhcp_leases(self):
        self.assertIn('/bin/ubus list "hostapd.*"', BACKEND)
        self.assertIn("/tmp/dhcp.leases", BACKEND)

    def test_update_check_is_required_before_update_buttons(self):
        view = (PACKAGE_ROOT / "htdocs/luci-static/resources/view/zarap/overview.js").read_text()
        self.assertIn("data.checked && data.update_available", view)

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
