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
        self.assertIn(
            "args: { enabled: true, outbounds: [], rules: [], clients: [], final: '' }",
            methods_body)

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
        self.assertIn("flush set inet fw4 ", BACKEND)
        # One transaction, and nft's own message has to reach the caller: an
        # earlier version sent it to /dev/null and left a failure unexplained.
        self.assertIn("/usr/sbin/nft -f ' + NFT_SYNC + ' 2>&1", BACKEND)
        self.assertIn("synced.output", BACKEND)
        self.assertIn("!synced.ok || !live_clients_match(live_guarded)", BACKEND)
        # The rollback path has to converge the kernel too, from the rules that
        # were restored rather than from the ones being applied.
        self.assertIn("guarded_macs(saved_rules())", BACKEND)
        self.assertIn("sync_live_sets(restored_guarded)", BACKEND)

    def test_the_kill_switch_outlives_the_master_switch(self):
        # A device named by a rule must not reach the WAN directly just because
        # the proxy was switched off; only deleting the rule opens that path.
        # The TProxy redirect is the part tied to the proxy running, since
        # sending traffic to a dead port would swallow it instead of rejecting.
        self.assertIn(
            "validate_candidate(request.outbounds, request.rules, request.final,",
            BACKEND)
        self.assertIn("let live_guarded = candidate.guarded;", BACKEND)
        self.assertIn("if (proxying)", BACKEND)
        self.assertNotIn("enabled ? request.rules : []", BACKEND)
        view = (PACKAGE_ROOT / "htdocs/luci-static/resources/view/zarap/overview.js").read_text()
        # The page marks a device held by the kill switch from the rules it is
        # showing, not from the guarded flag status reported: a device added to
        # a rule that has not been applied yet still needs its address field.
        self.assertIn("const killSwitch = state.firewall && guarded;", view)
        self.assertIn("function guardedMacs()", view)
        self.assertNotIn("device.guarded", view)

    def test_the_guarded_set_comes_only_from_the_rules(self):
        # Invariant 2: capture is a property of the network, the kill switch a
        # property of a device, and only a rule puts a device under it.
        self.assertIn("function guarded_macs(rules)", BACKEND)
        self.assertIn("for (let mac in guarded_macs(rules))", BACKEND)
        # Nothing may pull the set out of the device list or the capture.
        self.assertNotIn("zarap_clients_v4", BACKEND)
        self.assertNotIn("function read_clients()", BACKEND)

    def test_deselecting_a_device_releases_its_managed_lease(self):
        # zarap_managed was written and read but never acted on, so a static
        # lease outlived the selection that created it with no way to clear it.
        self.assertIn("uci.delete('dhcp', section)", BACKEND)
        self.assertIn("section.zarap_managed == '1' && !selected[", BACKEND)

    def test_rpcd_is_reloaded_rather_than_restarted(self):
        # A restart drops every ubus session and signs the user out of LuCI.
        # On SIGHUP rpcd freezes its sessions, re-execs and thaws them, which
        # picks up the plugin just the same.
        self.assertNotIn("rpcd restart", BACKEND)
        self.assertNotIn("rpcd restart", UCI_DEFAULTS)
        self.assertIn("/etc/init.d/rpcd reload", BACKEND)
        self.assertIn("/etc/init.d/rpcd reload", UCI_DEFAULTS)

    def test_device_discovery_covers_the_whole_lan(self):
        # Capture takes every device on the LAN, so a rule can name a wired host
        # too. Leases are the base of the list; hostapd only adds what a lease
        # cannot say — whether a station is associated, and on which radio.
        self.assertIn('/bin/ubus list "hostapd.*"', BACKEND)
        self.assertIn("/tmp/dhcp.leases", BACKEND)
        body = BACKEND.split("function device_list(", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("for (let mac in leases.by_mac)", body)
        self.assertIn("for (let mac in dynamic_leases)", body)
        # A device a rule names has to appear even with no lease at all.
        self.assertIn("for (let mac in guarded)", body)
        self.assertNotIn("wireless: true,", body)

    def test_update_check_is_required_before_update_buttons(self):
        view = (PACKAGE_ROOT / "htdocs/luci-static/resources/view/zarap/overview.js").read_text()
        self.assertIn("data.checked && data.update_available", view)

    def test_private_mac_detection_covers_locally_administered_bit(self):
        pattern = re.compile(r"^[0-9A-F][2367ABEF]:")
        self.assertRegex("02:00:00:00:00:01", pattern)
        self.assertRegex("A6:00:00:00:00:01", pattern)
        self.assertNotRegex("00:11:22:33:44:55", pattern)

    def test_fixed_tproxy_resources(self):
        for value in ("7893", "0x5a52", "2022", "zarap_guarded_v4"):
            self.assertIn(value, BACKEND + NFT)

    def test_kill_switch_covers_ipv4_and_ipv6(self):
        # The shipped file is the empty-but-safe state: the kill switch chain
        # exists with nothing in its set, and there is no capture yet. IPv6 is
        # barred for the whole LAN, which needs the interface the backend reads
        # at generation time, so those rules appear only in generated output.
        self.assertIn("ip saddr @zarap_guarded_v4 reject", NFT)
        self.assertNotIn("tproxy ip to", NFT)
        self.assertIn('ether type ip6 reject', BACKEND)
        self.assertNotIn("zarap_clients_mac", BACKEND + NFT)

    def test_the_masked_link_carries_the_saved_connection_name(self):
        # It used to end in a hardcoded #Zarap, discarding the name the link came
        # with. The name is a label, not a secret, so it survives round-tripping.
        self.assertIn("'#' + (outbound.label || 'Zarap')", BACKEND)
        self.assertIn("label: section.label || ''", BACKEND)

    def test_logs_scrub_every_connection(self):
        # Walking only the first section would leak the uuid of a second proxy
        # into the log the user copies out.
        logs_body = BACKEND.split("function logs()", 1)[1].split("function package_version", 1)[0]
        self.assertIn("for (let outbound in saved_outbounds())", logs_body)
        self.assertNotIn("uci.get('zarap', 'main', 'uuid')", logs_body)

    def test_ipv6_advertisement_is_turned_off_and_handed_back(self):
        # The capture is IPv4 only, so an advertised IPv6 would be a path around
        # sing-box for the whole LAN. It is somebody else's setting, so the
        # previous value is recorded on the first apply and restored on removal.
        self.assertIn("for (let key in ['ra', 'dhcpv6', 'ndp'])", BACKEND)
        self.assertIn("uci.set('dhcp', 'lan', key, 'disabled')", BACKEND)
        self.assertIn("uci.set('zarap', 'main', 'saved_' + key", BACKEND)
        self.assertIn("define Package/luci-app-zarap/prerm", MAKEFILE)
        self.assertIn("zarap.main.saved_$$key", MAKEFILE)

    def test_fixed_resources_are_not_pretend_settings(self):
        # They used to sit in uci looking configurable while every consumer
        # substituted the literal, so changing one produced a system that
        # disagreed with itself.
        config = (PACKAGE_ROOT / "root/etc/config/zarap").read_text()
        init = (PACKAGE_ROOT / "root/etc/init.d/zarap").read_text()
        for option in ("listen_port", "mark", "route_table"):
            self.assertNotIn(option, config)
        self.assertNotIn("config_get mark", init)
        self.assertNotIn("config_get route_table", init)
        self.assertIn("const CAPTURE_PORT = 7893", BACKEND)

    def test_status_does_not_return_proxy_secrets(self):
        status_body = BACKEND.split("function status()", 1)[1].split("function logs()", 1)[0]
        for secret_field in ("uuid:", "public_key:", "short_id:"):
            self.assertNotIn(secret_field, status_body)

    def test_every_function_is_defined_before_it_is_called(self):
        # ucode resolves a name where the call is compiled and does not hoist
        # function declarations, so a call placed above its own definition is
        # compiled as a global lookup, finds nothing and raises at runtime.
        # rpcd can only report that as UBUS_STATUS_UNKNOWN_ERROR, which reaches
        # the page as "Unspecified error (9)" — the whole of apply and validate
        # broke that way once validate_outbounds started calling
        # saved_outbounds, defined 500 lines below it.
        lines = BACKEND.split("\n")
        # Only top-level declarations: a nested one belongs to its enclosing
        # function and is not in scope for the rest of the file at all.
        declared = {}
        for number, line in enumerate(lines, 1):
            declaration = re.match(r"function ([A-Za-z_][A-Za-z0-9_]*)\(", line)
            if declaration:
                declared.setdefault(declaration.group(1), number)
        self.assertIn("saved_outbounds", declared)

        called_too_early = []
        for number, line in enumerate(lines, 1):
            code = re.sub(r"//.*", "", line)
            code = re.sub(r"'[^']*'|\"[^\"]*\"", "", code)
            for name in re.findall(r"(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
                if name in declared and declared[name] > number:
                    called_too_early.append(
                        f"line {number} calls {name}(), defined at line {declared[name]}"
                    )
        self.assertEqual(called_too_early, [])


if __name__ == "__main__":
    unittest.main()
