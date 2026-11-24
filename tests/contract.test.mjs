import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { PACKAGE_ROOT, ROOT } from './ucode_helper.mjs';

const BACKEND = readFileSync(join(PACKAGE_ROOT, 'root/usr/share/rpcd/ucode/zarap.uc'), 'utf8');
const NFT = readFileSync(join(PACKAGE_ROOT, 'root/etc/nftables.d/90-zarap.nft'), 'utf8');
const MAKEFILE = readFileSync(join(PACKAGE_ROOT, 'Makefile'), 'utf8');
const UCI_DEFAULTS = readFileSync(join(PACKAGE_ROOT, 'root/etc/uci-defaults/90-zarap'), 'utf8');
const VIEW = readFileSync(join(PACKAGE_ROOT, 'htdocs/luci-static/resources/view/zarap/overview.js'), 'utf8');

describe('package_contract', () => {
	test('repository has openwrt feed layout', () => {
		assert.equal(existsSync(join(ROOT, 'Makefile')), false);
		assert.ok(statSync(join(PACKAGE_ROOT, 'Makefile')).isFile());
		assert.ok(statSync(join(PACKAGE_ROOT, 'htdocs')).isDirectory());
		assert.ok(statSync(join(PACKAGE_ROOT, 'root')).isDirectory());
	});

	test('required package dependencies are declared', () => {
		for (const pkg of ['curl', 'firewall4', 'kmod-nft-tproxy', 'kmod-nft-socket', 'ip-full', 'ss'])
			assert.ok(MAKEFILE.includes(`+${pkg}`), pkg);
		assert.match(MAKEFILE, /LUCI_DEPENDS:=.*\bxray-core\b/);
		assert.equal(MAKEFILE.includes('sing-box'), false);
		assert.equal(MAKEFILE.includes('rpcd-mod-iwinfo'), false);
	});

	test('external binaries use their installed paths', () => {
		assert.equal(BACKEND.includes('/sbin/apk'), false);
		for (const path of ['/usr/bin/apk', '/usr/sbin/ss', '/usr/sbin/nft', '/usr/bin/xray', '/usr/bin/curl'])
			assert.ok(BACKEND.includes(path), path);
	});

	test('install does not stop a user-enabled xray service', () => {
		assert.equal(UCI_DEFAULTS.includes("uci -q set xray.enabled.enabled='0'"), false);
		assert.equal(UCI_DEFAULTS.includes('/etc/init.d/xray stop'), false);
		assert.ok(UCI_DEFAULTS.includes('/etc/zarap/assets'));
		assert.equal(UCI_DEFAULTS.includes('xray disable'), false);
		assert.ok(BACKEND.includes("uci.set('xray', 'enabled', 'enabled', enabled ? '1' : '0')"));
		assert.ok(BACKEND.includes("uci.set('xray', 'config', 'conffiles', [CONFIG])"));
		assert.ok(BACKEND.includes("uci.set('xray', 'config', 'datadir', ASSETS_DIR)"));
	});

	test('status separates an unmanaged xray', () => {
		assert.ok(BACKEND.includes('function unmanaged_xray()'));
		assert.ok(BACKEND.includes('не под управлением Zarap'));
	});

	test('installed version is read from a listing', () => {
		assert.equal(BACKEND.includes('apk info -v'), false);
		assert.ok(BACKEND.includes('/usr/bin/apk list -I '));
	});

	test('external commands use absolute paths', () => {
		const commands = [...BACKEND.matchAll(/(?:capture|system)\(\s*\[?\s*'([^']+)'/g)].map((m) => m[1]);
		assert.ok(commands.length > 0);
		for (const command of commands) {
			const leading = command.replace(/^[(\s]+/, '');
			assert.ok(leading.startsWith('/'), `not an absolute path: ${command}`);
		}
	});

	test('json manifests are valid', () => {
		for (const rel of [
			'root/usr/share/luci/menu.d/luci-app-zarap.json',
			'root/usr/share/rpcd/acl.d/luci-app-zarap.json'
		]) {
			JSON.parse(readFileSync(join(PACKAGE_ROOT, rel), 'utf8'));
		}
	});

	test('rpc namespace and update allowlist', () => {
		assert.ok(BACKEND.includes("return { 'zarap': methods };"));
		assert.ok(BACKEND.includes("'luci-app-zarap': true"));
		assert.ok(BACKEND.includes("'xray-core': true"));
		assert.equal(BACKEND.includes('apk upgrade'), false);
	});

	test('rpc surface matches specification', () => {
		const methodsBody = BACKEND.split('const methods = {')[1];
		for (const method of [
			'status', 'validate', 'apply', 'restart', 'stop', 'logs',
			'refresh_rulesets', 'updates', 'update_component'
		]) {
			assert.match(methodsBody, new RegExp(`\\b${method}:\\s*\\{`));
		}
		assert.doesNotMatch(methodsBody, /\bdevices:\s*\{/);
	});

	test('rpc args declare types by sample value', () => {
		const methodsBody = BACKEND.split('const methods = {')[1];
		for (const typeName of ["'bool'", "'string'", "'number'", "'array'", "'boolean'"])
			assert.equal(methodsBody.includes(typeName), false, typeName);
		assert.ok(methodsBody.includes('args: { refresh: true }'));

		const shared = [
			'outbounds: []', 'rules: []', 'rulesets: []', "ruleset_detour: ''",
			"ruleset_interval: ''", "bootstrap_dns: ''", 'resolve_all: true', 'clients: []', "final: ''"
		];
		for (const [method, expected] of [
			['validate', shared],
			['apply', ['enabled: true', ...shared]]
		]) {
			const body = methodsBody.match(new RegExp(`${method}: \\{\\s*args: \\{([\\s\\S]*?)\\},`));
			assert.ok(body, method);
			for (const pair of expected)
				assert.ok(body[1].includes(pair), `${method}: missing ${pair}`);
		}
	});

	test('init script keeps policy routing alive when rolling back to legacy sing-box', () => {
		const initScript = readFileSync(join(PACKAGE_ROOT, 'root/etc/init.d/zarap'), 'utf8');
		assert.ok(initScript.includes('LEGACY_CONFIG=/etc/zarap/sing-box.json'));
		assert.ok(initScript.includes('[ -s "$CONFIG" ] || [ -s "$LEGACY_CONFIG" ]'));
	});

	test('taking dns over is reversible', () => {
		assert.ok(BACKEND.includes("const DNS_TAKEOVER = ['server', 'noresolv', 'cachesize']"));
		assert.ok(BACKEND.includes('function dnsmasq_take_over('));
		assert.ok(BACKEND.includes('function dnsmasq_hand_back('));
		const takeOver = BACKEND.split('function dnsmasq_take_over(')[1].split('\n}')[0];
		assert.ok(takeOver.includes("saved_dns_' + key) == null"));
		const configure = BACKEND.split('function configure_dnsmasq(')[1].split('\n}')[0];
		assert.ok(configure.includes('if (enabled && resolve_all)'));
		assert.ok(configure.includes('dnsmasq_hand_back(uci, section)'));
		assert.ok(configure.includes('managed_dns_tracked'));
		assert.ok(configure.includes('managed_dns_servers'));
		assert.ok(MAKEFILE.includes('for key in server noresolv cachesize; do'));
		assert.ok(MAKEFILE.includes('saved_dns_'));
		assert.ok(MAKEFILE.includes('zarap.main.managed_dns_tracked'));
		assert.ok(MAKEFILE.includes('zarap.main.managed_dns_servers'));
		assert.equal(MAKEFILE.includes('grep -E'), false);
		assert.equal(MAKEFILE.includes('53(5[3-9]|[6-9][0-9])'), false);
	});

	test('the household resolver cannot be the router itself', () => {
		assert.ok(BACKEND.includes("resolve_all && bootstrap_result.value == 'local'"));
	});

	test('every rpc method is granted by the acl', () => {
		const acl = JSON.parse(
			readFileSync(join(PACKAGE_ROOT, 'root/usr/share/rpcd/acl.d/luci-app-zarap.json'), 'utf8')
		)['luci-app-zarap'];
		const granted = new Set([...acl.read.ubus.zarap, ...acl.write.ubus.zarap]);
		const methodsBody = BACKEND.split('const methods = {')[1];
		const declared = new Set([...methodsBody.matchAll(/^\t(\w+): \{/gm)].map((m) => m[1]));
		assert.deepEqual(declared, granted);
		assert.ok(acl.write.ubus.zarap.includes('refresh_rulesets'));
	});

	test('forced refresh can put the previous assets back and stale cleanup waits for check_runtime', () => {
		assert.ok(BACKEND.includes("const ASSETS_DIR = '/etc/zarap/assets'"));
		assert.ok(BACKEND.includes("const ASSETS_BACKUP_DIR = '/etc/zarap/.assets.bak'"));
		const refreshBody = BACKEND.split('function refresh_rulesets(')[1].split('\nfunction ')[0];
		assert.ok(refreshBody.includes('backup_assets()'));
		assert.ok(refreshBody.includes('restore_assets(backed.files)'));
		assert.ok(refreshBody.includes('xray_test(CONFIG)'));
		assert.ok(refreshBody.includes('check_runtime(true, LISTENER_WAIT)'));
		assert.ok(refreshBody.includes('startup_hint(rulesets)'));
		assert.ok(refreshBody.includes('if (!enabled) {'));

		const applyBody = BACKEND.split('function apply_configuration(')[1].split('\nfunction ')[0];
		const checkPos = applyBody.indexOf('check_runtime(enabled, LISTENER_WAIT)');
		const cleanupPos = applyBody.indexOf('cleanup_stale_assets(plan.assets)');
		assert.ok(checkPos > 0 && cleanupPos > checkPos, 'stale .dat cleanup must happen after check_runtime');
		assert.ok(applyBody.includes('legacy_zarap_sing_box()'));
		assert.ok(applyBody.includes('stop_legacy_sing_box()'));
	});

	test('atomic temporary files share target directories and xray temp keeps .json extension', () => {
		assert.ok(BACKEND.includes("const CONFIG_TMP = '/etc/zarap/.xray.tmp.json'"));
		assert.ok(BACKEND.includes("const NFT_TMP = '/etc/nftables.d/.90-zarap.nft.tmp'"));
		assert.ok(BACKEND.includes("const UCI_CANDIDATE = '/etc/config/.zarap-candidate'"));
		assert.ok(BACKEND.includes('cursor(UCI_CANDIDATE, UCI_CANDIDATE_DELTA)'));
		assert.ok(BACKEND.includes('activate_uci_candidate()'));
	});

	test('apply and updates verify complete runtime', () => {
		for (const check of [
			'running && listener && firewall && rule && route',
			'check_runtime(enabled)',
			'check_runtime(enabled, LISTENER_WAIT)',
			'check_runtime(true, LISTENER_WAIT)'
		]) {
			assert.ok(BACKEND.includes(check), check);
		}
		assert.equal(BACKEND.includes('check_runtime(true)'), false);
		assert.ok(BACKEND.includes('restore_update_files(backups'));
		assert.ok(BACKEND.includes('apk не смог обновить'));
		assert.ok(BACKEND.includes('restore_update_files(backups, true)'));
	});

	test('apply drives and verifies the live firewall sets', () => {
		assert.ok(BACKEND.includes('function sync_live_sets('));
		assert.ok(BACKEND.includes('function live_clients_match('));
		assert.ok(BACKEND.includes('flush set inet fw4 '));
		assert.ok(BACKEND.includes("/usr/sbin/nft -f ' + NFT_SYNC + ' 2>&1"));
		assert.ok(BACKEND.includes('synced.output'));
		assert.ok(BACKEND.includes('!synced.ok || !live_clients_match(live_guarded)'));
		assert.ok(BACKEND.includes('guarded_macs(saved_rules())'));
		assert.ok(BACKEND.includes('sync_live_sets(restored_guarded)'));
	});

	test('the kill switch outlives the master switch', () => {
		assert.ok(BACKEND.includes('validate_candidate(request.outbounds, request.rules, request.final,'));
		assert.ok(BACKEND.includes('let live_guarded = candidate.guarded;'));
		assert.ok(BACKEND.includes('if (proxying)'));
		assert.equal(BACKEND.includes('enabled ? request.rules : []'), false);
		assert.ok(VIEW.includes('const killSwitch = state.firewall && guarded;'));
		assert.ok(VIEW.includes('function guardedMacs()'));
		assert.equal(VIEW.includes('device.guarded'), false);
	});

	test('the guarded set comes only from the rules', () => {
		assert.ok(BACKEND.includes('function guarded_macs(rules)'));
		assert.ok(BACKEND.includes('for (let mac in guarded_macs(rules))'));
		assert.equal(BACKEND.includes('zarap_clients_v4'), false);
		assert.equal(BACKEND.includes('function read_clients()'), false);
	});

	test('deselecting a device releases its managed lease', () => {
		assert.ok(BACKEND.includes("uci.delete('dhcp', section)"));
		assert.ok(BACKEND.includes("section.zarap_managed == '1' && !selected["));
	});

	test('rpcd is reloaded rather than restarted', () => {
		assert.equal(BACKEND.includes('rpcd restart'), false);
		assert.equal(UCI_DEFAULTS.includes('rpcd restart'), false);
		assert.ok(BACKEND.includes('/etc/init.d/rpcd reload'));
		assert.ok(UCI_DEFAULTS.includes('/etc/init.d/rpcd reload'));
	});

	test('device discovery covers the whole lan', () => {
		assert.ok(BACKEND.includes('/bin/ubus list "hostapd.*"'));
		assert.ok(BACKEND.includes('/tmp/dhcp.leases'));
		const body = BACKEND.split('function device_list(')[1].split('\nfunction ')[0];
		assert.ok(body.includes('for (let mac in leases.by_mac)'));
		assert.ok(body.includes('for (let mac in dynamic_leases)'));
		assert.ok(body.includes('for (let mac in guarded)'));
		assert.equal(body.includes('wireless: true,'), false);
	});

	test('update check is required before update buttons', () => {
		assert.ok(VIEW.includes('data.checked && data.update_available'));
	});

	test('private mac detection covers locally administered bit', () => {
		const pattern = /^[0-9A-F][2367ABEF]:/;
		assert.match('02:00:00:00:00:01', pattern);
		assert.match('A6:00:00:00:00:01', pattern);
		assert.doesNotMatch('00:11:22:33:44:55', pattern);
	});

	test('fixed tproxy resources', () => {
		for (const value of ['7893', '0x5a52', '2022', 'zarap_guarded_v4'])
			assert.ok((BACKEND + NFT).includes(value), value);
	});

	test('kill switch covers ipv4 and ipv6', () => {
		assert.ok(NFT.includes('ip saddr @zarap_guarded_v4 reject'));
		assert.equal(NFT.includes('tproxy ip to'), false);
		assert.ok(BACKEND.includes('ether type ip6 reject'));
		assert.equal((BACKEND + NFT).includes('zarap_clients_mac'), false);
	});

	test('a connection has one shape on the wire', () => {
		assert.equal(BACKEND.includes('masked_link'), false);
		assert.ok(BACKEND.includes('function outbound_link(outbound)'));
		assert.ok(BACKEND.includes('link: outbound_link(outbound)'));
		assert.ok(BACKEND.includes("label: section.label || ''"));
		assert.ok(VIEW.includes('const HIDDEN_LINK'));
		assert.ok(VIEW.includes('shown ? outbound.link : HIDDEN_LINK'));
	});

	test('connections are named by the page', () => {
		assert.equal(BACKEND.includes('allocate_tag'), false);
		assert.ok(BACKEND.includes("return input_error('Подключение прислано без имени')"));
		assert.ok(VIEW.includes('function allocateTag()'));
	});

	test('logs scrub every connection', () => {
		const logsBody = BACKEND.split('function logs()')[1].split('function package_version')[0];
		assert.ok(logsBody.includes('for (let outbound in saved_outbounds())'));
		assert.equal(logsBody.includes("uci.get('zarap', 'main', 'uuid')"), false);
	});

	test('ipv6 advertisement is turned off and handed back', () => {
		assert.ok(BACKEND.includes("for (let key in ['ra', 'dhcpv6', 'ndp'])"));
		assert.ok(BACKEND.includes("uci.set('dhcp', 'lan', key, 'disabled')"));
		assert.ok(BACKEND.includes("uci.set('zarap', 'main', 'saved_' + key"));
		assert.ok(MAKEFILE.includes('define Package/luci-app-zarap/prerm'));
		assert.ok(MAKEFILE.includes('zarap.main.saved_$$key'));
	});

	test('fixed resources are not pretend settings', () => {
		const config = readFileSync(join(PACKAGE_ROOT, 'root/etc/config/zarap'), 'utf8');
		const init = readFileSync(join(PACKAGE_ROOT, 'root/etc/init.d/zarap'), 'utf8');
		for (const option of ['listen_port', 'mark', 'route_table'])
			assert.equal(config.includes(option), false, option);
		assert.equal(init.includes('config_get mark'), false);
		assert.equal(init.includes('config_get route_table'), false);
		assert.ok(BACKEND.includes('const CAPTURE_PORT = 7893'));
	});

	test('the log is still scrubbed', () => {
		const logsBody = BACKEND.split('function logs()')[1].split('\n// apk 3')[0];
		for (const secretField of ['uuid', 'public_key', 'short_id'])
			assert.ok(logsBody.includes(secretField), secretField);
		assert.ok(logsBody.includes("'vless://[скрыто]'"));
	});

	test('a lease zarap owns follows the page', () => {
		assert.ok(BACKEND.includes('if (existing && !existing.managed)'));
		assert.ok(BACKEND.includes('if (client.foreign_lease)'));
		assert.ok(BACKEND.includes('reconnect_required: !!held && held != client.ip'));
	});

	test('a device without a lease is offered an address', () => {
		assert.ok(BACKEND.includes('device.suggested_ip = suggest()'));
		assert.ok(BACKEND.includes('taken[lan.address] = true'));
		assert.ok(BACKEND.includes('for (let ip, lease in static_leases().by_ip)'));
		assert.ok(BACKEND.includes('for (let mac, lease in current_dhcp_leases())'));
	});

	test('every function is defined before it is called', () => {
		const lines = BACKEND.split('\n');
		const declared = {};
		lines.forEach((line, idx) => {
			const m = line.match(/^function ([A-Za-z_][A-Za-z0-9_]*)\(/);
			if (m && !(m[1] in declared))
				declared[m[1]] = idx + 1;
		});
		assert.ok('saved_outbounds' in declared);

		const calledTooEarly = [];
		lines.forEach((line, idx) => {
			const number = idx + 1;
			let code = line.replace(/\/\/.*/, '');
			code = code.replace(/'[^']*'|"[^"]*"/g, '');
			for (const m of code.matchAll(/(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\s*\(/g)) {
				const name = m[1];
				if (name in declared && declared[name] > number)
					calledTooEarly.push(`line ${number} calls ${name}(), defined at line ${declared[name]}`);
			}
		});
		assert.deepEqual(calledTooEarly, []);
	});
});
