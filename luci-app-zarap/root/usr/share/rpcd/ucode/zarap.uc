#!/usr/bin/env ucode

'use strict';

import { access, chmod, mkdir, open, popen, readfile, rename, unlink, writefile } from 'fs';
import { urldecode, urldecode_params } from 'luci.http';
import { connect } from 'ubus';
import { cursor } from 'uci';

const CONFIG = '/etc/zarap/sing-box.json';
const CONFIG_TMP = '/etc/zarap/.sing-box.json.tmp';
const NFT_CONFIG = '/etc/nftables.d/90-zarap.nft';
const NFT_TMP = '/etc/nftables.d/.90-zarap.nft.tmp';
const NFT_CHECK = '/tmp/zarap-nft-check.conf';
const NFT_SYNC = '/tmp/zarap-nft-sync.conf';
const UCI_CANDIDATE = '/etc/config/.zarap-candidate';
const UCI_CANDIDATE_DELTA = '/tmp/.zarap-uci';
const UCI_CONFIGS = ['zarap', 'dhcp', 'sing-box'];
const COMPONENTS = { 'luci-app-zarap': true, 'sing-box': true };
const LOCK_FILE = '/var/lock/zarap.lock';
// Seconds a freshly started sing-box gets to open its TProxy port. Kept well
// inside the LuCI RPC deadline.
const LISTENER_WAIT = 5;

function result_error(message, details, kind) {
	return { ok: false, error: message, details: details || '', kind: kind || 'operation_error' };
}

function input_error(message) {
	return result_error(message, '', 'input_error');
}

function capture(command) {
	let fd = popen(command, 'r');
	if (!fd)
		return { code: -1, output: '' };

	let output = fd.read('all') || '';
	return { code: fd.close(), output: trim(output) };
}

function acquire_lock() {
	let fd = open(LOCK_FILE, 'w');
	if (!fd || !fd.lock('xn')) {
		if (fd) fd.close();
		return null;
	}
	return fd;
}

function release_lock(fd) {
	if (!fd) return;
	fd.lock('u');
	fd.close();
}

function normalize_mac(value) {
	let mac = uc(trim('' + (value || '')));
	return match(mac, /^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/) ? mac : null;
}

function is_private_mac(mac) {
	return !!match(mac || '', /^[0-9A-F][2367ABEF]:/);
}

function valid_ipv4(value) {
	if (!match(value || '', /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/))
		return false;

	for (let part in split(value, '.'))
		if (int(part) < 0 || int(part) > 255)
			return false;

	return true;
}

function parse_vless(link) {
	link = trim('' + (link || ''));

	// Links arrive pasted from chats and web pages, which slip in non-breaking
	// spaces, zero-width characters and a leading BOM. A stray one next to the
	// port made it read as "443 " and the link was rejected for an out-of-range
	// port. Everything a link needs outside its display fragment is printable
	// ASCII, and that fragment is dropped below, so discard the rest.
	link = replace(link, /[^!-~]+/g, '');

	if (!match(link, /^vless:\/\//))
		return input_error('Ссылка должна начинаться с vless://');

	let fragment_at = index(link, '#');
	if (fragment_at >= 0)
		link = substr(link, 0, fragment_at);

	let query_at = index(link, '?');
	let rest = query_at >= 0 ? substr(link, 8, query_at - 8) : substr(link, 8);
	let query = query_at >= 0 ? substr(link, query_at + 1) : '';

	// RFC 3986: the authority ends at the first '/'. Share links routinely
	// carry an empty path there, and leaving it in put the slash inside the
	// port and rejected the link.
	let path_at = index(rest, '/');
	let authority = path_at >= 0 ? substr(rest, 0, path_at) : rest;
	let at = rindex(authority, '@');
	if (at <= 0)
		return input_error('В ссылке отсутствуют UUID или адрес сервера');

	let uuid = lc(urldecode(substr(authority, 0, at)) || '');
	let endpoint = substr(authority, at + 1);
	let server, port_text;

	if (substr(endpoint, 0, 1) == '[') {
		let closing = index(endpoint, ']');
		if (closing < 2 || substr(endpoint, closing + 1, 1) != ':')
			return input_error('Некорректный IPv6-адрес сервера');
		server = substr(endpoint, 1, closing - 1);
		port_text = substr(endpoint, closing + 2);
	}
	else {
		let colon = rindex(endpoint, ':');
		if (colon <= 0)
			return input_error('В ссылке отсутствует порт сервера');
		server = urldecode(substr(endpoint, 0, colon)) || '';
		port_text = substr(endpoint, colon + 1);
	}

	let port = int(port_text);
	if (!match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/))
		return input_error('Некорректный UUID');
	if (!match(server, /^[A-Za-z0-9._:-]+$/))
		return input_error('Некорректный адрес сервера');
	if (!match(port_text, /^[0-9]+$/) || port < 1 || port > 65535)
		return input_error('Порт сервера должен быть от 1 до 65535');

	let params = urldecode_params(query);
	let security = lc(params.security || '');
	let transport = lc(params.type || 'tcp');
	let flow = params.flow || '';
	let encryption = lc(params.encryption || 'none');
	let sni = params.sni || params.serverName || '';
	let public_key = params.pbk || params.publicKey || '';
	let short_id = params.sid || params.shortId || '';
	let fingerprint = params.fp || 'chrome';

	if (security != 'reality')
		return input_error('MVP поддерживает только VLESS Reality');
	if (transport != 'tcp')
		return input_error('MVP поддерживает только транспорт TCP');
	if (flow != '' && flow != 'xtls-rprx-vision')
		return input_error('Поддерживается только flow xtls-rprx-vision');
	if (encryption != '' && encryption != 'none')
		return input_error('Для VLESS параметр encryption должен быть none');
	if (!match(sni, /^[A-Za-z0-9.-]+$/))
		return input_error('В Reality-ссылке отсутствует корректный SNI');
	if (!match(public_key, /^[A-Za-z0-9_-]{32,64}$/))
		return input_error('В Reality-ссылке отсутствует корректный публичный ключ');
	if (short_id != '' && !match(short_id, /^[0-9A-Fa-f]{2,32}$/))
		return input_error('Short ID должен быть чётной шестнадцатеричной строкой');
	if (length(short_id) % 2 != 0)
		return input_error('Short ID должен содержать чётное число символов');
	if (!match(fingerprint, /^[A-Za-z0-9_-]+$/))
		return input_error('Некорректный fingerprint');

	return {
		ok: true,
		config: {
			server: server,
			server_port: port,
			uuid: uuid,
			flow: flow,
			server_name: sni,
			public_key: public_key,
			short_id: short_id,
			fingerprint: fingerprint
		}
	};
}

function validate_clients(clients) {
	if (clients == null)
		clients = [];
	if (type(clients) != 'array')
		return input_error('Список устройств имеет неверный формат');

	let result = [], seen_mac = {}, seen_ip = {};
	for (let client in clients) {
		let mac = normalize_mac(client?.mac);
		let ip = trim('' + (client?.ip || ''));
		let name = trim('' + (client?.name || ''));

		if (!mac)
			return input_error('У одного из устройств некорректный MAC-адрес');
		if (is_private_mac(mac))
			return input_error('Устройство ' + mac + ' использует приватный MAC. Отключите рандомизацию MAC для этой Wi-Fi-сети.');
		if (!valid_ipv4(ip))
			return input_error('Для устройства ' + mac + ' нужен корректный статический IPv4-адрес');
		if (seen_mac[mac] || seen_ip[ip])
			return input_error('MAC- и IPv4-адреса выбранных устройств не должны повторяться');
		if (length(name) > 63 || (name != '' && !match(name, /^[A-Za-z0-9А-Яа-яЁё_. -]+$/)))
			return input_error('Имя устройства содержит недопустимые символы');

		seen_mac[mac] = true;
		seen_ip[ip] = true;
		push(result, { mac: mac, ip: ip, name: name || ('zarap-' + replace(mac, /:/g, '')) });
	}

	return { ok: true, clients: result };
}

function sing_box_config(parsed, listen_port) {
	let outbound = {
		type: 'vless',
		tag: 'zarap-proxy',
		server: parsed.server,
		server_port: parsed.server_port,
		uuid: parsed.uuid,
		tls: {
			enabled: true,
			server_name: parsed.server_name,
			utls: { enabled: true, fingerprint: parsed.fingerprint },
			reality: { enabled: true, public_key: parsed.public_key }
		}
	};

	if (parsed.flow)
		outbound.flow = parsed.flow;
	if (parsed.short_id)
		outbound.tls.reality.short_id = parsed.short_id;

	return {
		log: { level: 'info', timestamp: true },
		inbounds: [{
			type: 'tproxy',
			tag: 'zarap-tproxy',
			listen: '0.0.0.0',
			listen_port: listen_port
		}],
		outbounds: [outbound],
		route: { auto_detect_interface: true, final: 'zarap-proxy' }
	};
}

function network_v4(address, mask) {
	if (!valid_ipv4(address) || mask < 0 || mask > 32)
		return null;

	let source = split(address, '.'), output = [], left = mask;
	for (let octet in source) {
		let bits = left >= 8 ? 8 : (left > 0 ? left : 0);
		let netmask = bits == 0 ? 0 : (256 - (1 << (8 - bits)));
		push(output, int(octet) & netmask);
		left -= bits;
	}
	return join('.', output) + '/' + mask;
}

// True when a CIDR already falls inside one of the entries. The LAN discovered
// over ubus is normally inside the RFC1918 ranges listed below, and an interval
// set rejects overlapping elements. auto-merge would absorb them, but a set
// created before that flag was added keeps its old definition through every
// reload, so the overlap has to be avoided rather than merged away.
function v4_covered(cidr, entries) {
	let parts = split(cidr, '/');
	let mask = length(parts) > 1 ? int(parts[1]) : 32;
	for (let entry in entries) {
		let entry_parts = split(entry, '/');
		let entry_mask = length(entry_parts) > 1 ? int(entry_parts[1]) : 32;
		if (entry_mask <= mask &&
			network_v4(parts[0], entry_mask) != null &&
			network_v4(parts[0], entry_mask) == network_v4(entry_parts[0], entry_mask))
			return true;
	}
	return false;
}

function direct_networks() {
	let v4 = [
		'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
		'169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
		'224.0.0.0/4', '255.255.255.255'
	];
	let v6 = ['::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8'];
	let ubus = connect();

	if (ubus) {
		let lan = ubus.call('network.interface.lan', 'status') || {};
		for (let item in (lan['ipv4-address'] || [])) {
			let cidr = network_v4(item?.address || '', int(item?.mask));
			if (cidr && !v4_covered(cidr + '/' + int(item?.mask), v4))
				push(v4, cidr);
		}
		// Only a global unicast prefix adds anything: unique-local, link-local
		// and multicast are already covered by fc00::/7, fe80::/10 and ff00::/8,
		// and repeating them would overlap.
		for (let item in (lan['ipv6-prefix'] || []))
			if (match(item?.address || '', /^[23][0-9A-Fa-f]*:[0-9A-Fa-f:]*$/) &&
				int(item?.mask) >= 0 && int(item?.mask) <= 128)
				push(v6, item.address + '/' + int(item.mask));
		ubus.disconnect();
	}

	return { v4: v4, v6: v6 };
}

function nft_set(name, type_name, flags, elements) {
	let text = 'set ' + name + ' {\n\ttype ' + type_name + '\n';
	if (flags) {
		text += '\tflags ' + flags + '\n';
		// The LAN prefixes discovered at runtime normally sit inside the static
		// RFC1918 and fc00::/7 entries, and an interval set rejects overlapping
		// elements outright. Have nftables merge them instead of failing.
		if (index(flags, 'interval') >= 0)
			text += '\tauto-merge\n';
	}
	if (length(elements))
		text += '\telements = { ' + join(', ', elements) + ' }\n';
	return text + '}\n\n';
}

// A selected device must never reach the WAN directly, so the kill switch holds
// whether or not the proxy is running. The TProxy redirect is the part that
// depends on it: pointing traffic at a port nothing listens on would swallow it
// silently, while leaving only the kill switch rejects it outright.
function nft_config(clients, listen_port, proxying) {
	let ips = map(clients, function(client) { return client.ip; });
	let macs = map(clients, function(client) { return client.mac; });
	let direct = direct_networks();
	let text = '# Generated by Zarap. Manual changes will be overwritten.\n';

	text += nft_set('zarap_clients_v4', 'ipv4_addr', '', ips);
	text += nft_set('zarap_clients_mac', 'ether_addr', '', macs);
	text += nft_set('zarap_direct_v4', 'ipv4_addr', 'interval', direct.v4);
	text += nft_set('zarap_direct_v6', 'ipv6_addr', 'interval', direct.v6);
	text += 'chain zarap_prerouting {\n';
	text += '\ttype filter hook prerouting priority mangle; policy accept;\n';
	text += '\tip saddr @zarap_clients_v4 ip daddr @zarap_direct_v4 return\n';
	if (proxying)
		text += '\tip saddr @zarap_clients_v4 meta l4proto { tcp, udp } meta mark set 0x5a52 tproxy ip to 127.0.0.1:' + listen_port + ' accept\n';
	text += '}\n\n';
	text += 'chain zarap_killswitch_forward {\n';
	text += '\ttype filter hook forward priority filter + 10; policy accept;\n';
	text += '\tip saddr @zarap_clients_v4 ip daddr @zarap_direct_v4 return\n';
	text += '\tip saddr @zarap_clients_v4 reject\n';
	text += '\tether saddr @zarap_clients_mac ether type ip6 ip6 daddr @zarap_direct_v6 return\n';
	text += '\tether saddr @zarap_clients_mac ether type ip6 reject\n';
	text += '}\n\n';
	text += 'chain zarap_protect_tproxy {\n';
	text += '\ttype filter hook input priority filter - 10; policy accept;\n';
	text += '\tmeta l4proto { tcp, udp } th dport ' + listen_port + ' meta mark != 0x5a52 drop\n';
	text += '}\n';
	return text;
}

function static_leases() {
	let uci = cursor(), by_mac = {}, by_ip = {};
	uci.load('dhcp');
	uci.foreach('dhcp', 'host', function(section) {
		let raw_mac = type(section.mac) == 'array' ? section.mac[0] : section.mac;
		let mac = normalize_mac(raw_mac);
		let ip = section.ip || '';
		if (!mac || !valid_ipv4(ip))
			return;
		let lease = {
			section: section['.name'], mac: mac, ip: ip,
			name: section.name || '', managed: section.zarap_managed == '1'
		};
		by_mac[mac] = lease;
		by_ip[ip] = lease;
	});
	return { by_mac: by_mac, by_ip: by_ip };
}

function current_dhcp_leases() {
	let by_mac = {};
	for (let line in split(readfile('/tmp/dhcp.leases') || '', '\n')) {
		let fields = split(trim(line), /[ \t]+/);
		if (length(fields) < 4)
			continue;
		let mac = normalize_mac(fields[1]);
		if (!mac || !valid_ipv4(fields[2]))
			continue;
		by_mac[mac] = {
			mac: mac,
			ip: fields[2],
			name: fields[3] == '*' ? '' : fields[3]
		};
	}
	return by_mac;
}

function ipv4_in_lan(ip) {
	let ubus = connect();
	if (!ubus)
		return false;
	let lan = ubus.call('network.interface.lan', 'status') || {};
	ubus.disconnect();
	for (let item in (lan['ipv4-address'] || [])) {
		let mask = int(item?.mask);
		if (network_v4(ip, mask) == network_v4(item?.address || '', mask))
			return true;
	}
	return false;
}

function resolve_static_leases(clients) {
	let leases = static_leases(), dynamic = current_dhcp_leases(), result = [];
	for (let client in clients) {
		let existing = leases.by_mac[client.mac];
		if (existing) {
			push(result, {
				mac: client.mac, ip: existing.ip,
				name: client.name || existing.name, has_static_lease: true
			});
			continue;
		}
		let conflict = leases.by_ip[client.ip];
		if (conflict && conflict.mac != client.mac)
			return input_error('IPv4-адрес ' + client.ip + ' уже закреплён за ' + conflict.mac);
		if (!ipv4_in_lan(client.ip))
			return input_error('IPv4-адрес ' + client.ip + ' не входит в LAN-подсеть');
		push(result, {
			mac: client.mac, ip: client.ip, name: client.name,
			has_static_lease: false,
			reconnect_required: !!dynamic[client.mac]?.ip && dynamic[client.mac].ip != client.ip
		});
	}
	return { ok: true, clients: result };
}

function configure_uci(uci, parsed, enabled, clients) {
	uci.load('zarap');
	uci.set('zarap', 'main', 'zarap');
	uci.set('zarap', 'main', 'enabled', enabled ? '1' : '0');
	for (let key in ['server', 'server_port', 'uuid', 'flow', 'server_name', 'public_key', 'short_id', 'fingerprint'])
		uci.set('zarap', 'main', key, '' + parsed[key]);
	uci.set('zarap', 'main', 'listen_port', '7893');
	uci.set('zarap', 'main', 'mark', '0x5a52');
	uci.set('zarap', 'main', 'route_table', '2022');

	let old_clients = [];
	uci.foreach('zarap', 'client', function(section) { push(old_clients, section['.name']); });
	for (let section in old_clients)
		uci.delete('zarap', section);
	for (let client in clients) {
		let section = uci.add('zarap', 'client');
		uci.set('zarap', section, 'mac', client.mac);
		uci.set('zarap', section, 'ip', client.ip);
		uci.set('zarap', section, 'name', client.name);
	}
	uci.load('dhcp');

	// Zarap marks the static leases it creates with zarap_managed. Nothing ever
	// removed them, so a device kept its pinned address after being deselected
	// and there was no way to release it from the interface. Drop the marked
	// leases whose device is no longer in the list; the ones still selected stay,
	// because resolve_static_leases has already recognised them.
	let selected = {};
	for (let client in clients)
		selected[client.mac] = true;
	let stale = [];
	uci.foreach('dhcp', 'host', function(section) {
		let raw_mac = type(section.mac) == 'array' ? section.mac[0] : section.mac;
		if (section.zarap_managed == '1' && !selected[normalize_mac(raw_mac)])
			push(stale, section['.name']);
	});
	for (let section in stale)
		uci.delete('dhcp', section);

	for (let client in clients) {
		if (client.has_static_lease)
			continue;
		let section = 'zarap_' + lc(replace(client.mac, /:/g, ''));
		uci.set('dhcp', section, 'host');
		uci.set('dhcp', section, 'name', client.name);
		uci.set('dhcp', section, 'mac', client.mac);
		uci.set('dhcp', section, 'ip', client.ip);
		uci.set('dhcp', section, 'zarap_managed', '1');
	}
	uci.load('sing-box');
	uci.set('sing-box', 'main', 'sing-box');
	uci.set('sing-box', 'main', 'enabled', enabled ? '1' : '0');
	uci.set('sing-box', 'main', 'user', 'root');
	uci.set('sing-box', 'main', 'conffile', CONFIG);
	uci.set('sing-box', 'main', 'workdir', '/tmp/zarap');
	return true;
}

function cleanup_uci_candidate() {
	for (let name in UCI_CONFIGS) {
		unlink(UCI_CANDIDATE + '/' + name);
		unlink(UCI_CANDIDATE_DELTA + '/' + name);
	}
}

function prepare_uci_candidate(parsed, enabled, clients) {
	mkdir(UCI_CANDIDATE);
	chmod(UCI_CANDIDATE, 0700);
	mkdir(UCI_CANDIDATE_DELTA);
	chmod(UCI_CANDIDATE_DELTA, 0700);
	cleanup_uci_candidate();

	for (let name in UCI_CONFIGS) {
		let content = readfile('/etc/config/' + name);
		if (writefile(UCI_CANDIDATE + '/' + name, content == null ? '' : content) == null) {
			cleanup_uci_candidate();
			return result_error('Не удалось создать временный UCI-кандидат', '', 'startup_error');
		}
	}

	let candidate = cursor(UCI_CANDIDATE, UCI_CANDIDATE_DELTA);
	if (!configure_uci(candidate, parsed, enabled, clients)) {
		cleanup_uci_candidate();
		return result_error('Не удалось сформировать временный UCI-кандидат', '', 'startup_error');
	}
	for (let name in UCI_CONFIGS)
		if (!candidate.commit(name)) {
			cleanup_uci_candidate();
			return result_error('Временный UCI-кандидат не прошёл проверку', '', 'compatibility_error');
		}

	return { ok: true };
}

function activate_uci_candidate() {
	for (let name in UCI_CONFIGS)
		if (!rename(UCI_CANDIDATE + '/' + name, '/etc/config/' + name))
			return false;
	chmod('/etc/config/zarap', 0600);
	return true;
}

function read_clients() {
	let uci = cursor(), clients = [];
	uci.load('zarap');
	uci.foreach('zarap', 'client', function(section) {
		push(clients, {
			mac: normalize_mac(section.mac) || '',
			ip: section.ip || '',
			name: section.name || ''
		});
	});
	return clients;
}

function saved_proxy_config() {
	let uci = cursor();
	uci.load('zarap');
	let server = uci.get('zarap', 'main', 'server') || '';
	if (!server)
		return null;
	return {
		server: server,
		server_port: int(uci.get('zarap', 'main', 'server_port') || 0),
		uuid: uci.get('zarap', 'main', 'uuid') || '',
		flow: uci.get('zarap', 'main', 'flow') || '',
		server_name: uci.get('zarap', 'main', 'server_name') || '',
		public_key: uci.get('zarap', 'main', 'public_key') || '',
		short_id: uci.get('zarap', 'main', 'short_id') || '',
		fingerprint: uci.get('zarap', 'main', 'fingerprint') || 'chrome'
	};
}

function masked_proxy(parsed) {
	if (!parsed)
		return '';
	return 'vless://********@' + parsed.server + ':' + parsed.server_port +
		'?security=reality&type=tcp&sni=' + parsed.server_name +
		(parsed.flow ? '&flow=' + parsed.flow : '') + '#Zarap';
}

function tproxy_listening() {
	let listeners = capture('/usr/sbin/ss -H -lntup sport = :7893').output;
	return !!(listeners && index(lc(listeners), 'sing-box') >= 0);
}

// procd returns from a restart once it has signalled the service, not once the
// service is ready, and sing-box needs a moment to bind ("started (0.22s)").
// Checking straight away failed a working configuration and rolled it back, so
// callers that have just started the service wait a little for the port.
function check_runtime(enabled, wait_seconds) {
	if (!enabled)
		return { ok: true, running: false, listener: false, firewall: false, routing: false };

	let running = system(['/etc/init.d/sing-box', 'running']) == 0;
	let listener = tproxy_listening();
	for (let waited = 0; !listener && waited < (wait_seconds || 0); waited++) {
		system(['/bin/sleep', '1']);
		listener = tproxy_listening();
	}
	let firewall = system('/usr/sbin/nft list chain inet fw4 zarap_killswitch_forward >/dev/null 2>&1') == 0 &&
		system('/usr/sbin/nft list chain inet fw4 zarap_prerouting >/dev/null 2>&1') == 0;
	let rule = system('/sbin/ip -4 rule show | grep -q "fwmark 0x5a52.*lookup 2022"') == 0;
	let route = system('/sbin/ip -4 route show table 2022 | grep -Eq "^local (default|0.0.0.0/0) dev lo"') == 0;
	return {
		ok: running && listener && firewall && rule && route,
		running: running,
		listener: !!listener,
		firewall: firewall,
		routing: rule && route
	};
}

function recent_connection_error() {
	let output = lc(capture('/sbin/logread -e sing-box -l 80').output);
	for (let marker in [
		'connection refused', 'network is unreachable', 'i/o timeout',
		'connection reset', 'reality handshake', 'tls handshake'
	])
		if (index(output, marker) >= 0)
			return true;
	return false;
}

function validate_candidate(parsed, clients, proxying) {
	mkdir('/etc/zarap');
	chmod('/etc/zarap', 0700);
	let sing_box = sprintf('%J', sing_box_config(parsed, 7893)) + '\n';
	let nft = nft_config(clients, 7893, proxying);
	let config_written = writefile(CONFIG_TMP, sing_box);
	let nft_written = writefile(NFT_TMP, nft);
	if (config_written == null || nft_written == null) {
		unlink(CONFIG_TMP); unlink(NFT_TMP);
		return result_error('Не удалось создать временные файлы конфигурации', '', 'startup_error');
	}
	chmod(CONFIG_TMP, 0600);
	if (writefile(NFT_CHECK, 'table inet zarap_check {\n' + nft + '}\n') == null) {
		unlink(CONFIG_TMP); unlink(NFT_TMP);
		return result_error('Не удалось создать файл проверки nftables', '', 'startup_error');
	}

	if (system(['/usr/bin/sing-box', 'check', '-c', CONFIG_TMP]) != 0) {
		unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
		return result_error('Установленный sing-box отклонил сгенерированную конфигурацию', '', 'compatibility_error');
	}
	if (system(['/usr/sbin/nft', '-c', '-f', NFT_CHECK]) != 0) {
		unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
		return result_error('nftables отклонил сгенерированные правила', '', 'compatibility_error');
	}
	return { ok: true, sing_box: sing_box, nft: nft };
}

// firewall4 rebuilds the chains from the generated file but leaves the contents
// of existing sets alone: a set declared without elements does not clear one
// that is already populated. Reloading with an empty client list therefore left
// the previous addresses in the kernel, so a deselected device stayed in the
// kill switch and kept having its traffic sent to a TProxy port nothing was
// listening on. Drive the live sets to the intended contents explicitly.
function sync_live_sets(clients) {
	let ips = [], macs = [], direct = direct_networks();
	for (let client in clients) {
		if (client.ip) push(ips, client.ip);
		if (client.mac) push(macs, client.mac);
	}
	let wanted = {
		zarap_clients_v4: ips,
		zarap_clients_mac: macs,
		zarap_direct_v4: direct.v4,
		zarap_direct_v6: direct.v6
	};

	// One transaction, so the sets never sit half-updated, and the output is
	// kept: swallowing nft's message here left a failure with nothing to act on.
	let script = '';
	for (let name, elements in wanted) {
		script += 'flush set inet fw4 ' + name + '\n';
		if (length(elements))
			script += 'add element inet fw4 ' + name + ' { ' + join(', ', elements) + ' }\n';
	}
	if (writefile(NFT_SYNC, script) == null)
		return { ok: false, output: 'не удалось записать ' + NFT_SYNC };

	let applied = capture('/usr/sbin/nft -f ' + NFT_SYNC + ' 2>&1');
	unlink(NFT_SYNC);
	return { ok: applied.code == 0, output: applied.output };
}

// Reads back what the kernel holds, so an apply cannot report success while the
// device is still caught by rules that were only cleared on paper.
function live_clients_match(clients) {
	let live = capture('/usr/sbin/nft list set inet fw4 zarap_clients_v4').output;
	for (let client in clients)
		if (client.ip && index(live, client.ip) < 0)
			return false;
	if (!length(clients) && index(live, 'elements') >= 0)
		return false;
	return true;
}

function rollback(backups) {
	let ok = true;
	for (let path, content in backups) {
		if (content == null)
			unlink(path);
		else if (writefile(path, content) == null)
			ok = false;
	}
	chmod('/etc/config/zarap', 0600);
	unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK); cleanup_uci_candidate();
	if (system(['/etc/init.d/firewall', 'reload']) != 0) ok = false;
	// The restored selection keeps its kill switch whatever the master switch says.
	let resynced = sync_live_sets(read_clients());
	if (!resynced.ok) {
		system('/usr/bin/logger -t zarap "nft sync failed during rollback: ' + replace(resynced.output, /"/g, "'") + '"');
		ok = false;
	}
	if (system(['/etc/init.d/dnsmasq', 'restart']) != 0) ok = false;
	if (system(['/etc/init.d/zarap', 'restart']) != 0) ok = false;
	if (system(['/etc/init.d/sing-box', 'restart']) != 0) ok = false;
	return ok;
}

function restore_update_files(backups, restart_proxy) {
	let ok = true;
	for (let path, content in backups) {
		if (content == null)
			unlink(path);
		else if (writefile(path, content) == null)
			ok = false;
	}
	chmod('/etc/config/zarap', 0600);
	if (system(['/etc/init.d/firewall', 'reload']) != 0) ok = false;
	if (system(['/etc/init.d/zarap', 'restart']) != 0) ok = false;
	if (restart_proxy) {
		if (system(['/etc/init.d/sing-box', 'restart']) != 0) ok = false;
	}
	else {
		system(['/etc/init.d/sing-box', 'stop']);
	}
	return ok;
}

function resource_conflict() {
	let listeners = capture('/usr/sbin/ss -H -lntup sport = :7893').output;
	if (listeners && (!saved_proxy_config() || index(lc(listeners), 'sing-box') < 0))
		return result_error('Порт 7893 уже занят другим процессом');

	let routes = capture('/sbin/ip -4 route show table 2022').output;
	for (let line in split(routes, '\n'))
		if (trim(line) && !match(trim(line), /^local (default|0\.0\.0\.0\/0) dev lo( |$)/))
			return result_error('Таблица маршрутизации 2022 уже используется другой конфигурацией');

	let rules = capture('/sbin/ip -4 rule show').output;
	for (let line in split(rules, '\n'))
		if (index(line, 'fwmark 0x5a52') >= 0 && index(line, 'lookup 2022') < 0)
			return result_error('Packet mark 0x5a52 уже используется другой таблицей маршрутизации');

	// nft prints the mark zero-padded, as "0x00005a52", so looking for the
	// literal 0x5a52 never matched and this guard did nothing. Zarap's own mark
	// also appears in zarap_protect_tproxy, which has to count as ours or every
	// apply would report a conflict against itself.
	let nft_rules = capture('/usr/sbin/nft -a list ruleset').output;
	let own_rules = capture('/usr/sbin/nft -a list chain inet fw4 zarap_prerouting').output +
		capture('/usr/sbin/nft -a list chain inet fw4 zarap_protect_tproxy').output;
	for (let line in split(nft_rules, '\n'))
		if (match(line, /0x0*5a52/) && index(own_rules, trim(line)) < 0)
			return result_error('Packet mark 0x5a52 уже используется другим правилом nftables');

	return { ok: true };
}

function apply_configuration(args) {
	let link = trim('' + (args?.link || ''));
	let parsed_result;
	if (link) {
		parsed_result = parse_vless(link);
		if (!parsed_result.ok)
			return parsed_result;
	}
	else {
		let saved = saved_proxy_config();
		if (!saved)
			return input_error('Для первоначальной настройки вставьте VLESS Reality-ссылку');
		parsed_result = { ok: true, config: saved };
	}
	let client_result = validate_clients(args?.clients);
	if (!client_result.ok)
		return client_result;
	client_result = resolve_static_leases(client_result.clients);
	if (!client_result.ok)
		return client_result;
	let conflict = resource_conflict();
	if (!conflict.ok)
		return conflict;

	let enabled = !!args?.enabled;
	let candidate = validate_candidate(parsed_result.config, client_result.clients, enabled);
	if (!candidate.ok)
		return candidate;
	let uci_candidate = prepare_uci_candidate(parsed_result.config, enabled, client_result.clients);
	if (!uci_candidate.ok) {
		unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
		return uci_candidate;
	}

	let backups = {};
	for (let path in ['/etc/config/zarap', '/etc/config/dhcp', '/etc/config/sing-box', CONFIG, NFT_CONFIG])
		backups[path] = readfile(path);
	if (backups[CONFIG] != null) {
		writefile(CONFIG + '.bak', backups[CONFIG]);
		chmod(CONFIG + '.bak', 0600);
	}

	if (!activate_uci_candidate()) {
		let restored = rollback(backups);
		return result_error(restored ? 'Не удалось атомарно активировать UCI; изменения отменены' :
			'Критическая ошибка активации UCI и rollback; kill switch не отключался', '', 'startup_error');
	}
	if (system(['/etc/init.d/dnsmasq', 'restart']) != 0) {
		let restored = rollback(backups);
		return result_error(restored ? 'dnsmasq не принял static DHCP lease; изменения отменены' :
			'Критическая ошибка dnsmasq и rollback; kill switch не отключался', '', 'startup_error');
	}

	if (!rename(CONFIG_TMP, CONFIG) || !rename(NFT_TMP, NFT_CONFIG)) {
		let restored = rollback(backups);
		return result_error(restored ? 'Не удалось атомарно активировать файлы; изменения отменены' :
			'Критическая ошибка активации файлов и rollback; kill switch не отключался', '', 'startup_error');
	}
	chmod(CONFIG, 0600);
	unlink(NFT_CHECK);

	if (system(['/etc/init.d/firewall', 'reload']) != 0) {
		let restored = rollback(backups);
		return result_error(restored ? 'firewall4 не принял правила Zarap; восстановлена предыдущая конфигурация' :
			'Критическая ошибка firewall4 и rollback; загруженный kill switch не отключался', '', 'startup_error');
	}

	// Selected devices stay in the sets even with Zarap switched off; releasing
	// one means deselecting it, which is the only thing that opens its WAN path.
	let live_clients = client_result.clients;
	let synced = sync_live_sets(live_clients);
	if (!synced.ok || !live_clients_match(live_clients)) {
		let restored = rollback(backups);
		return result_error(restored ? 'Правила firewall в ядре не совпали с сохранёнными; восстановлена предыдущая конфигурация' :
			'Критическая ошибка синхронизации правил и rollback; kill switch оставлен активным',
			synced.output, 'startup_error');
	}

	let service_code;
	if (enabled) {
		service_code = system(['/etc/init.d/zarap', 'restart']);
		if (service_code == 0)
			service_code = system(['/etc/init.d/sing-box', 'restart']);
	}
	else {
		system(['/etc/init.d/sing-box', 'stop']);
		service_code = system(['/etc/init.d/zarap', 'stop']);
	}
	if (service_code != 0) {
		let restored = rollback(backups);
		return result_error(restored ? 'Не удалось запустить Zarap; восстановлена предыдущая конфигурация' :
			'Критическая ошибка запуска и rollback; kill switch оставлен активным', '', 'startup_error');
	}

	let health = check_runtime(enabled, LISTENER_WAIT);
	if (!health.ok) {
		let restored = rollback(backups);
		return result_error(restored ? 'Локальная инфраструктура Zarap не прошла проверку; конфигурация восстановлена' :
			'Критическая ошибка проверки и rollback; kill switch оставлен активным', sprintf('%J', health), 'startup_error');
	}

	return { ok: true, enabled: enabled, clients: client_result.clients, health: health };
}

function device_list() {
	let devices = {}, selected = {}, leases = static_leases();
	let dynamic_leases = current_dhcp_leases();
	for (let client in read_clients())
		selected[client.mac] = client;

	let ubus = connect();
	if (ubus) {
		let objects = split(capture('/bin/ubus list "hostapd.*"').output, '\n');
		for (let object in objects) {
			if (!match(object, /^hostapd\.[A-Za-z0-9_.-]+$/))
				continue;
			let response = ubus.call(object, 'get_clients') || {};
			for (let raw_mac, station in (response.clients || {})) {
				let mac = normalize_mac(raw_mac);
				if (!mac) continue;
				let lease = leases.by_mac[mac] || {};
				let dynamic = dynamic_leases[mac] || {};
				devices[mac] = {
					mac: mac,
					name: lease.name || dynamic.name || selected[mac]?.name || ('Устройство ' + mac),
					ip: lease.ip || dynamic.ip || selected[mac]?.ip || '',
					connected: true,
					wireless: true,
					network: substr(object, 8),
					signal: station?.signal || 0,
					has_static_lease: !!lease.ip,
					private_mac: is_private_mac(mac),
					selected: !!selected[mac]
				};
			}
		}
		ubus.disconnect();
	}

	for (let mac, client in selected)
		if (!devices[mac]) {
			let lease = leases.by_mac[mac] || {};
			devices[mac] = {
				mac: mac,
				name: lease.name || client.name || ('Устройство ' + mac),
				ip: lease.ip || client.ip,
				connected: false,
				wireless: true,
				has_static_lease: !!lease.ip,
				private_mac: is_private_mac(mac),
				selected: true
			};
		}

	let result = [];
	for (let mac, device in devices)
		push(result, device);
	return result;
}

// True while the sing-box service runs on somebody else's configuration. Its
// failures then belong to that configuration, not to Zarap, and saying so keeps
// a crash-looping package default from reading as a Zarap fault.
function unmanaged_sing_box() {
	let uci = cursor();
	uci.load('sing-box');
	return (uci.get('sing-box', 'main', 'conffile') || '') != CONFIG &&
		uci.get('sing-box', 'main', 'enabled') == '1';
}

function status() {
	let uci = cursor();
	uci.load('zarap');
	let enabled = uci.get('zarap', 'main', 'enabled') == '1';
	let configured = !!uci.get('zarap', 'main', 'server');
	let health = check_runtime(enabled);
	let state = 'disabled', message = 'Zarap выключен';
	let held = !enabled && length(read_clients()) > 0;
	if (!configured) {
		state = 'not_configured';
		message = unmanaged_sing_box() ?
			'Прокси ещё не настроен: вставьте VLESS Reality-ссылку. Служба sing-box сейчас работает не под управлением Zarap, со своей конфигурацией — её ошибки в журнале к Zarap не относятся' :
			'Прокси ещё не настроен: вставьте VLESS Reality-ссылку и включите Zarap';
	}
	else if (access(CONFIG) && system(['/usr/bin/sing-box', 'check', '-c', CONFIG]) != 0) {
		state = 'compatibility_error';
		message = 'Установленный sing-box не принимает текущую конфигурацию';
	}
	else if (enabled && !health.ok) {
		state = 'startup_error';
		message = 'Процесс, TProxy, nftables или policy routing не прошли проверку';
	}
	else if (enabled && recent_connection_error()) {
		state = 'connection_error';
		message = 'Локальная инфраструктура работает, но в журнале есть ошибка соединения с прокси';
	}
	else if (enabled) {
		state = 'working';
		message = 'Zarap работает';
	}
	else if (held) {
		message = 'Zarap выключен. Отмеченные устройства остаются без выхода в интернет: kill switch не пускает их напрямую. Снимите отметку с устройства, чтобы вернуть ему прямой доступ';
	}
	let saved = saved_proxy_config();

	return {
		ok: true,
		enabled: enabled,
		configured: configured,
		state: state,
		message: message,
		running: health.running,
		listener: health.listener,
		firewall: health.firewall,
		routing: health.routing,
		masked_link: masked_proxy(saved),
		devices: device_list()
	};
}

function logs() {
	let uci = cursor();
	uci.load('zarap');
	let secrets = [
		uci.get('zarap', 'main', 'uuid') || '',
		uci.get('zarap', 'main', 'public_key') || '',
		uci.get('zarap', 'main', 'short_id') || ''
	];
	let output = capture('/sbin/logread -e zarap -e sing-box').output;
	let lines = split(output, '\n');
	if (length(lines) > 200)
		lines = slice(lines, length(lines) - 200);
	output = join('\n', lines);
	for (let secret in secrets)
		if (secret)
			while (index(output, secret) >= 0)
				output = replace(output, secret, '[скрыто]');
	output = replace(output, /vless:\/\/[^ \t\r\n"'<>]+/g, 'vless://[скрыто]');
	output = replace(output, /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}/g, '[скрыто]');
	output = replace(output, /"(public_key|private_key|short_id)"[ \t]*:[ \t]*"[^"]*"/g, '"секрет":"[скрыто]"');
	return { ok: true, logs: output };
}

// apk 3 answers `info -v` with description lines ("name: summary"), never a
// version, so the installed version has to come from `list -I`, which prints
// "<name>-<version> <arch> {origin} (license) [installed]" — the same shape
// the upgradable listing uses.
function package_version(name) {
	let found = capture('/usr/bin/apk list -I ' + name + ' 2>/dev/null').output;
	let prefix = name + '-';
	for (let line in split(found, '\n')) {
		let value = split(trim(line), /[ \t]+/)[0] || '';
		if (index(value, prefix) == 0)
			return substr(value, length(prefix));
	}
	return '';
}

function candidate_version(name, line) {
	let value = split(line || '', /[ \t]+/)[0] || '';
	let prefix = name + '-';
	return index(value, prefix) == 0 ? substr(value, length(prefix)) : value;
}

function updates(refresh) {
	let refresh_code = 0, refresh_output = '';
	if (refresh) {
		// Keep apk's own message: an exit code alone leaves the user with
		// nothing to act on when a repository or its key is misconfigured.
		let refreshed = capture('/usr/bin/apk update 2>&1');
		refresh_code = refreshed.code;
		refresh_output = refreshed.output;
	}
	let upgradeable = capture('/usr/bin/apk list --upgradable 2>/dev/null').output;
	let components = {};
	for (let name in keys(COMPONENTS)) {
		let line = '';
		for (let candidate in split(upgradeable, '\n'))
			if (match(candidate, regexp('^' + name + '-')))
				line = candidate;
		components[name] = {
			installed: package_version(name),
			checked: refresh && refresh_code == 0,
			update_available: refresh && line != '',
			candidate: candidate_version(name, line)
		};
	}
	if (refresh_code != 0)
		return {
			ok: false,
			error: 'apk не смог обновить списки репозиториев',
			details: refresh_output,
			kind: 'operation_error',
			refresh_code: refresh_code,
			components: components
		};
	return { ok: true, refresh_code: refresh_code, components: components };
}

function update_component(name) {
	if (!COMPONENTS[name])
		return result_error('Обновление этого пакета запрещено');

	let current = status();
	if (current.enabled && !current.firewall)
		return result_error('Обновление запрещено: kill switch не активен');

	let backups = {};
	for (let path in ['/etc/config/zarap', '/etc/config/sing-box', CONFIG, NFT_CONFIG]) {
		let content = readfile(path);
		backups[path] = content;
		if (content != null) {
			writefile(path + '.bak', content);
			chmod(path + '.bak', 0600);
		}
	}

	if (name == 'sing-box')
		system(['/etc/init.d/sing-box', 'stop']);

	let code = system(['/usr/bin/apk', 'add', '--upgrade', name]);
	if (code != 0) {
		let recovered = name != 'sing-box' || !current.enabled || restore_update_files(backups, true);
		return result_error('apk не смог обновить ' + name + (recovered ?
			'; предыдущая конфигурация восстановлена, kill switch активен' :
			'; восстановление сервиса не удалось, kill switch оставлен активным'), '', 'startup_error');
	}

	if (access(CONFIG) && system(['/usr/bin/sing-box', 'check', '-c', CONFIG]) != 0) {
		restore_update_files(backups, false);
		return result_error('Новая версия sing-box не принимает текущий конфиг; файлы восстановлены, сервис остановлен, kill switch активен', '', 'compatibility_error');
	}
	if (name == 'luci-app-zarap' && system([
		'/usr/bin/ucode', '-cdynlink=fs,dynlink=luci.http,dynlink=ubus,dynlink=uci',
		'-o', '/tmp/zarap-update.uc', '/usr/share/rpcd/ucode/zarap.uc'
	]) != 0) {
		restore_update_files(backups, current.enabled);
		return result_error('Новый код Zarap не прошёл проверку; конфигурационные файлы восстановлены, kill switch активен', '', 'compatibility_error');
	}
	unlink('/tmp/zarap-update.uc');

	if (system(['/etc/init.d/firewall', 'reload']) != 0) {
		restore_update_files(backups, current.enabled);
		return result_error('После обновления firewall4 отклонил правила; файлы восстановлены, kill switch не отключался', '', 'startup_error');
	}

	if (current.enabled) {
		if (system(['/etc/init.d/zarap', 'restart']) != 0 || system(['/etc/init.d/sing-box', 'restart']) != 0) {
			restore_update_files(backups, true);
			return result_error('Пакет обновлён, но сервис не запустился; файлы восстановлены, kill switch активен', '', 'startup_error');
		}
		let health = check_runtime(true, LISTENER_WAIT);
		if (!health.ok) {
			restore_update_files(backups, true);
			return result_error('После обновления не прошла проверка процесса, TProxy, nftables или маршрутизации; файлы восстановлены', sprintf('%J', health), 'startup_error');
		}
	}

	if (name == 'luci-app-zarap')
		// reload rather than restart: rpcd re-execs on SIGHUP and thaws its sessions,
		// so updating Zarap no longer signs the user out of LuCI.
		system('(/bin/sleep 1; /etc/init.d/rpcd reload) >/dev/null 2>&1 &');
	return { ok: true, component: name, reload_required: name == 'luci-app-zarap' };
}

// rpcd builds each ubus policy from the *type* of the sample value given
// here, so a type name like 'bool' declares a string argument and the real
// boolean call is rejected with UBUS_STATUS_INVALID_ARGUMENT.
const methods = {
	status: { call: function() { return status(); } },
	validate: {
		args: { link: '', clients: [] },
		call: function(request) {
			let link = trim('' + (request.args?.link || ''));
			let parsed = link ? parse_vless(link) : { ok: true, config: saved_proxy_config() };
			if (!parsed.ok) return parsed;
			if (!parsed.config) return input_error('Для первоначальной проверки вставьте VLESS Reality-ссылку');
			let clients = validate_clients(request.args?.clients);
			if (!clients.ok) return clients;
			clients = resolve_static_leases(clients.clients);
			if (!clients.ok) return clients;
			let conflict = resource_conflict();
			if (!conflict.ok) return conflict;
			let candidate = validate_candidate(parsed.config, clients.clients, true);
			if (!candidate.ok) return candidate;
			let uci_candidate = prepare_uci_candidate(parsed.config, true, clients.clients);
			unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK); cleanup_uci_candidate();
			if (!uci_candidate.ok) return uci_candidate;
			return { ok: true, masked_link: masked_proxy(parsed.config), clients: length(clients.clients) };
		}
	},
	apply: {
		args: { link: '', enabled: true, clients: [] },
		call: function(request) {
			let lock = acquire_lock();
			if (!lock) return result_error('Другая операция Zarap уже выполняется');
			let result = apply_configuration(request.args || {});
			release_lock(lock);
			return result;
		}
	},
	restart: {
		call: function() {
			let code = system(['/etc/init.d/zarap', 'restart']);
			if (code == 0)
				code = system(['/etc/init.d/sing-box', 'restart']);
			let health = code == 0 ? check_runtime(true, LISTENER_WAIT) : { ok: false };
			return code == 0 && health.ok ? { ok: true, health: health } :
				result_error('После перезапуска не прошла проверка процесса, TProxy, nftables или маршрутизации', sprintf('%J', health), 'startup_error');
		}
	},
	stop: {
		call: function() {
			let code = system(['/etc/init.d/sing-box', 'stop']);
			let firewall = system('/usr/sbin/nft list chain inet fw4 zarap_killswitch_forward >/dev/null 2>&1') == 0;
			return code == 0 && firewall ? { ok: true, kill_switch: true } :
				result_error('Не удалось безопасно остановить sing-box с активным kill switch', '', 'startup_error');
		}
	},
	logs: { call: function() { return logs(); } },
	updates: {
		args: { refresh: true },
		call: function(request) {
			let refresh = !!request.args?.refresh;
			if (!refresh) return updates(false);
			let lock = acquire_lock();
			if (!lock) return result_error('Другая операция Zarap уже выполняется');
			let result = updates(true);
			release_lock(lock);
			return result;
		}
	},
	update_component: {
		args: { name: '' },
		call: function(request) {
			let name = request.args?.name || '';
			let lock = acquire_lock();
			if (!lock) return result_error('Другая операция Zarap уже выполняется');
			let result = update_component(name);
			release_lock(lock);
			return result;
		}
	}
};

return { 'zarap': methods };
