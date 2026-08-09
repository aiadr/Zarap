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

// Fixed resources. These used to live in uci and read like settings, but every
// consumer here substituted the literals anyway, so changing one produced a
// broken system complaining about a port it was no longer using. They are
// constants; /etc/init.d/zarap carries the same values for the policy routing.
const CAPTURE_PORT = 7893;
const MARK = '0x5a52';
const ROUTE_TABLE = 2022;
const INBOUND_TAG = 'zarap-tproxy';

// Outbound section names double as sing-box tags, so they have to stay clear of
// the tags sing-box gives its own meanings.
const RESERVED_TAGS = { direct: true, block: true, dns: true, main: true, [INBOUND_TAG]: true };

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

	// The fragment carries the name the client gave the connection. Take it
	// before the filter below, which would eat the spaces in it, and keep it
	// readable: it is shown back to the user and stored in uci, so control
	// characters have to go and the length needs a bound.
	let name = '';
	let fragment_at = index(link, '#');
	if (fragment_at >= 0) {
		name = trim(replace(urldecode(substr(link, fragment_at + 1)) || '', /[[:cntrl:]]/g, ''));
		if (length(name) > 64)
			name = trim(substr(name, 0, 64));
		link = substr(link, 0, fragment_at);
	}

	// Links arrive pasted from chats and web pages, which slip in non-breaking
	// spaces, zero-width characters and a leading BOM. A stray one next to the
	// port made it read as "443 " and the link was rejected for an out-of-range
	// port. Everything a link needs outside the fragment is printable ASCII.
	link = replace(link, /[^!-~]+/g, '');

	if (!match(link, /^vless:\/\//))
		return input_error('Ссылка должна начинаться с vless://');

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
			name: name,
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

// Connections are addressed by their section name, which is also their sing-box
// tag, so a name has to survive editing the link behind it. New ones get the
// lowest free number; the ones already saved keep what they have.
function allocate_tag(taken) {
	for (let n = 1; n <= 999; n++)
		if (!taken['out_' + n])
			return 'out_' + n;
	return null;
}

// An entry with an empty link keeps the secret already saved under that tag, so
// applying an unchanged connection never sends its uuid through the browser.
function validate_outbounds(input) {
	if (input == null)
		input = [];
	if (type(input) != 'array')
		return input_error('Список подключений имеет неверный формат');

	let saved = {}, taken = {}, result = [];
	for (let outbound in saved_outbounds())
		saved[outbound.tag] = outbound;

	for (let entry in input) {
		let tag = trim('' + (entry?.tag || ''));
		if (!tag)
			continue;
		if (!valid_outbound_tag(tag))
			return input_error('Некорректное имя подключения: ' + tag);
		if (taken[tag])
			return input_error('Подключения не должны повторяться: ' + tag);
		taken[tag] = true;
	}

	for (let entry in input) {
		let tag = trim('' + (entry?.tag || ''));
		let link = trim('' + (entry?.link || ''));
		let label = trim(replace('' + (entry?.label || ''), /[[:cntrl:]]/g, ''));
		let config;

		if (link) {
			let parsed = parse_vless(link);
			if (!parsed.ok)
				return parsed;
			config = parsed.config;
			if (!label)
				label = config.name;
		}
		else {
			if (!tag || !saved[tag])
				return input_error('Для нового подключения нужна VLESS Reality-ссылка');
			config = saved[tag];
			if (!label)
				label = config.label;
		}

		if (!tag) {
			tag = allocate_tag(taken);
			if (!tag)
				return input_error('Слишком много подключений');
			taken[tag] = true;
		}

		if (length(label) > 64)
			label = trim(substr(label, 0, 64));
		push(result, {
			tag: tag,
			label: label,
			server: config.server,
			server_port: config.server_port,
			uuid: config.uuid,
			flow: config.flow,
			server_name: config.server_name,
			public_key: config.public_key,
			short_id: config.short_id,
			fingerprint: config.fingerprint || 'chrome'
		});
	}
	return { ok: true, outbounds: result };
}

function valid_target(target, tags) {
	return target == 'direct' || target == 'block' || !!tags[target];
}

function validate_rules(input, tags) {
	if (input == null)
		input = [];
	if (type(input) != 'array')
		return input_error('Список правил имеет неверный формат');

	let result = [];
	for (let entry in input) {
		let target = trim('' + (entry?.target || ''));
		if (!valid_target(target, tags))
			return input_error('Правило ссылается на несуществующее подключение: ' + (target || '—'));

		let raw = entry?.clients;
		if (raw == null)
			raw = [];
		if (type(raw) != 'array')
			return input_error('Список устройств в правиле имеет неверный формат');

		let seen = {}, clients = [];
		for (let value in raw) {
			let mac = normalize_mac(value);
			if (!mac)
				return input_error('В правиле указан некорректный MAC-адрес');
			if (is_private_mac(mac))
				return input_error('Устройство ' + mac + ' использует приватный MAC. Отключите рандомизацию MAC для этой Wi-Fi-сети.');
			if (seen[mac])
				return input_error('Устройство ' + mac + ' указано в правиле дважды');
			seen[mac] = true;
			push(clients, mac);
		}
		// A rule with no condition would match everything and duplicate the
		// remainder, which main.final already covers.
		if (!length(clients))
			return input_error('В правиле должно быть хотя бы одно устройство');
		push(result, { clients: clients, target: target });
	}
	return { ok: true, rules: result };
}

function valid_outbound_tag(tag) {
	return !!match(tag || '', /^out_[0-9]+$/) && !RESERVED_TAGS[tag];
}

function outbound_json(outbound) {
	let json = {
		type: 'vless',
		tag: outbound.tag,
		server: outbound.server,
		server_port: outbound.server_port,
		uuid: outbound.uuid,
		tls: {
			enabled: true,
			server_name: outbound.server_name,
			utls: { enabled: true, fingerprint: outbound.fingerprint || 'chrome' },
			reality: { enabled: true, public_key: outbound.public_key }
		}
	};

	if (outbound.flow)
		json.flow = outbound.flow;
	if (outbound.short_id)
		json.tls.reality.short_id = outbound.short_id;
	return json;
}

// sing-box cannot match a source by MAC, so a device is represented by the
// address its static lease pins. address_of maps one to the other.
function rule_json(rule, address_of) {
	let sources = [];
	for (let mac in (rule.clients || [])) {
		let address = address_of[mac];
		if (address)
			push(sources, address + '/32');
	}

	// The inbound is the only one there is, so naming it changes nothing today.
	// It is written from the start so that splitting the capture across several
	// TProxy ports later does not mean rewriting every rule.
	let json = { inbound: [INBOUND_TAG] };
	if (length(sources))
		json.source_ip_cidr = sources;
	// The special `block` outbound was deprecated in sing-box 1.11 and removed
	// in 1.13; the rule action replaces it.
	if (rule.target == 'block')
		json.action = 'reject';
	else
		json.outbound = rule.target;
	return json;
}

function sing_box_config(outbounds, rules, final, address_of) {
	let emitted = [], route_rules = [], wants_direct = false;

	for (let outbound in outbounds)
		push(emitted, outbound_json(outbound));

	for (let rule in rules) {
		push(route_rules, rule_json(rule, address_of || {}));
		if (rule.target == 'direct')
			wants_direct = true;
	}

	// `final` takes an outbound tag, and `block` is no longer one. Blocking the
	// remainder is therefore a trailing rule that matches everything, with the
	// field itself filled by a declared tag so it stays valid — the flow never
	// reaches it.
	let final_tag = final;
	if (final == 'block') {
		push(route_rules, { inbound: [INBOUND_TAG], action: 'reject' });
		final_tag = length(outbounds) ? outbounds[0].tag : 'direct';
	}
	if (final_tag == 'direct')
		wants_direct = true;

	// Declared only when something points at it: an unreferenced `direct` would
	// turn a mistyped tag into a silent path to the WAN, while an undeclared one
	// makes `sing-box check` reject the configuration outright.
	if (wants_direct)
		push(emitted, { type: 'direct', tag: 'direct' });

	return {
		log: { level: 'info', timestamp: true },
		inbounds: [{
			type: 'tproxy',
			tag: INBOUND_TAG,
			listen: '0.0.0.0',
			listen_port: CAPTURE_PORT
		}],
		outbounds: emitted,
		route: { auto_detect_interface: true, rules: route_rules, final: final_tag }
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

// The device the LAN is bridged onto. Read on every generation rather than
// baked in: a redirect rule without an interface condition would capture
// traffic arriving from the WAN too, so an unanswered ubus has to fail the
// apply instead of producing an unrestricted rule.
function lan_device() {
	let ubus = connect();
	if (!ubus)
		return '';
	let lan = ubus.call('network.interface.lan', 'status') || {};
	ubus.disconnect();
	let device = trim('' + (lan.l3_device || lan.device || ''));
	return match(device, /^[A-Za-z0-9._-]+$/) ? device : '';
}

// Two different jobs, two different sources. The redirect captures everything
// arriving from the LAN and knows nothing about devices. The kill switch holds
// only the devices named in a rule, and holds them whether or not the proxy is
// running — releasing one means deleting its rule.
//
// The redirect itself is the part tied to the master switch: pointing traffic
// at a port nothing listens on would swallow it silently, so switching Zarap
// off drops the rule and the LAN forwards normally again.
function nft_config(guarded_ips, lan, proxying) {
	let direct = direct_networks();
	let text = '# Generated by Zarap. Manual changes will be overwritten.\n';

	text += nft_set('zarap_guarded_v4', 'ipv4_addr', '', guarded_ips);
	text += nft_set('zarap_direct_v4', 'ipv4_addr', 'interval', direct.v4);
	text += nft_set('zarap_direct_v6', 'ipv6_addr', 'interval', direct.v6);
	text += 'chain zarap_prerouting {\n';
	text += '\ttype filter hook prerouting priority mangle; policy accept;\n';
	// Keeps the router itself, traffic between LAN subnets, multicast and
	// broadcast out of the capture. Without it dnsmasq's own port goes to TProxy.
	text += '\tiifname "' + lan + '" ip daddr @zarap_direct_v4 return\n';
	if (proxying)
		text += '\tiifname "' + lan + '" meta l4proto { tcp, udp } meta mark set ' + MARK + ' tproxy ip to 127.0.0.1:' + CAPTURE_PORT + ' accept\n';
	text += '}\n\n';
	text += 'chain zarap_killswitch_forward {\n';
	text += '\ttype filter hook forward priority filter + 10; policy accept;\n';
	text += '\tip saddr @zarap_guarded_v4 ip daddr @zarap_direct_v4 return\n';
	text += '\tip saddr @zarap_guarded_v4 reject\n';
	// IPv6 is not proxied, and it is not handed out to the LAN either, so there
	// is no device to single out here: the whole LAN is barred from routing it.
	// That also covers an address someone configured by hand.
	text += '\tiifname "' + lan + '" ether type ip6 ip6 daddr @zarap_direct_v6 return\n';
	text += '\tiifname "' + lan + '" ether type ip6 reject\n';
	text += '}\n\n';
	text += 'chain zarap_protect_tproxy {\n';
	text += '\ttype filter hook input priority filter - 10; policy accept;\n';
	text += '\tmeta l4proto { tcp, udp } th dport ' + CAPTURE_PORT + ' meta mark != ' + MARK + ' drop\n';
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

function configure_uci(uci, outbounds, rules, final, enabled, clients) {
	uci.load('zarap');
	uci.set('zarap', 'main', 'zarap');
	uci.set('zarap', 'main', 'enabled', enabled ? '1' : '0');
	uci.set('zarap', 'main', 'final', final);
	// Leftovers from the single-connection schema and from the three options
	// that only ever looked like settings.
	for (let key in ['name', 'server', 'server_port', 'uuid', 'flow', 'server_name',
	                 'public_key', 'short_id', 'fingerprint',
	                 'listen_port', 'mark', 'route_table'])
		uci.delete('zarap', 'main', key);

	// The whole set is rewritten on every apply, which is also what makes the
	// order of the rule sections the order of the rules.
	let stale = [];
	for (let kind in ['outbound', 'rule', 'client'])
		uci.foreach('zarap', kind, function(section) { push(stale, section['.name']); });
	for (let section in stale)
		uci.delete('zarap', section);

	for (let outbound in outbounds) {
		uci.set('zarap', outbound.tag, 'outbound');
		uci.set('zarap', outbound.tag, 'label', outbound.label);
		uci.set('zarap', outbound.tag, 'type', 'vless');
		for (let key in ['server', 'server_port', 'uuid', 'flow', 'server_name',
		                 'public_key', 'short_id', 'fingerprint'])
			uci.set('zarap', outbound.tag, key, '' + outbound[key]);
	}
	for (let rule in rules) {
		let section = uci.add('zarap', 'rule');
		uci.set('zarap', section, 'client', rule.clients);
		uci.set('zarap', section, 'target', rule.target);
	}
	uci.load('dhcp');

	// Zarap marks the static leases it creates with zarap_managed. Nothing ever
	// removed them, so a device kept its pinned address after its rule was gone
	// and there was no way to release it from the interface. Drop the marked
	// leases whose device is no longer named by any rule; the ones still named
	// stay, because resolve_static_leases has already recognised them.
	let selected = {};
	for (let client in clients)
		selected[client.mac] = true;
	let stale_leases = [];
	uci.foreach('dhcp', 'host', function(section) {
		let raw_mac = type(section.mac) == 'array' ? section.mac[0] : section.mac;
		if (section.zarap_managed == '1' && !selected[normalize_mac(raw_mac)])
			push(stale_leases, section['.name']);
	});
	for (let section in stale_leases)
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

	// The capture is IPv4 only, so an advertised IPv6 would be a path around
	// sing-box for the whole LAN. Not handing it out beats rejecting it packet
	// by packet: a device that never gets a global address never tries to use
	// one, instead of falling back to IPv4 on every connection.
	//
	// This holds whether or not Zarap is enabled, to match the blanket IPv6
	// reject in the kill switch chain — restoring advertisement while that rule
	// stands would hand out addresses that cannot work.
	for (let key in ['ra', 'dhcpv6', 'ndp']) {
		let previous = uci.get('dhcp', 'lan', key);
		// Recorded once, on the first apply, so removing the package can put
		// back what the router had rather than a guess at the default.
		if (uci.get('zarap', 'main', 'saved_' + key) == null)
			uci.set('zarap', 'main', 'saved_' + key, previous == null ? '' : previous);
		uci.set('dhcp', 'lan', key, 'disabled');
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

function prepare_uci_candidate(outbounds, rules, final, enabled, clients) {
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
	if (!configure_uci(candidate, outbounds, rules, final, enabled, clients)) {
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

function saved_outbounds() {
	let uci = cursor(), outbounds = [];
	uci.load('zarap');
	uci.foreach('zarap', 'outbound', function(section) {
		let tag = section['.name'];
		if (!valid_outbound_tag(tag))
			return;
		push(outbounds, {
			tag: tag,
			label: section.label || '',
			server: section.server || '',
			server_port: int(section.server_port || 0),
			uuid: section.uuid || '',
			flow: section.flow || '',
			server_name: section.server_name || '',
			public_key: section.public_key || '',
			short_id: section.short_id || '',
			fingerprint: section.fingerprint || 'chrome'
		});
	});
	return outbounds;
}

// The order of the sections in the file is the order of the rules, and the
// first match wins — so this must not be sorted or deduplicated on the way out.
function saved_rules() {
	let uci = cursor(), rules = [];
	uci.load('zarap');
	uci.foreach('zarap', 'rule', function(section) {
		let raw = section.client;
		if (type(raw) != 'array')
			raw = raw ? [raw] : [];
		let clients = [];
		for (let value in raw) {
			let mac = normalize_mac(value);
			if (mac)
				push(clients, mac);
		}
		push(rules, { clients: clients, target: section.target || '' });
	});
	return rules;
}

function saved_final() {
	let uci = cursor();
	uci.load('zarap');
	return uci.get('zarap', 'main', 'final') || 'direct';
}

// Every device named by a rule is guarded, whatever that rule targets, and it
// stays guarded until the last rule naming it is deleted.
function guarded_macs(rules) {
	let macs = {};
	for (let rule in rules)
		for (let mac in rule.clients)
			macs[mac] = true;
	return macs;
}

function lease_addresses() {
	let leases = static_leases(), address_of = {};
	for (let mac, lease in leases.by_mac)
		address_of[mac] = lease.ip;
	return address_of;
}

// Which target a device's traffic actually reaches: the first rule naming it
// wins, and a device no rule names falls through to the configured remainder.
function resolved_target(mac, rules, final) {
	for (let rule in rules)
		for (let named in rule.clients)
			if (named == mac)
				return rule.target;
	return final;
}

function masked_link(outbound) {
	if (!outbound)
		return '';
	return 'vless://********@' + outbound.server + ':' + outbound.server_port +
		'?security=reality&type=tcp&sni=' + outbound.server_name +
		(outbound.flow ? '&flow=' + outbound.flow : '') +
		'#' + (outbound.label || 'Zarap');
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
	// The kill switch holds whether or not the proxy is running, so its state
	// has to be reported truthfully even with Zarap switched off. Reporting a
	// blanket false here made the page claim the rules were gone while they
	// were still blocking the selected devices.
	let firewall = system('/usr/sbin/nft list chain inet fw4 zarap_killswitch_forward >/dev/null 2>&1') == 0 &&
		system('/usr/sbin/nft list chain inet fw4 zarap_prerouting >/dev/null 2>&1') == 0;
	if (!enabled)
		return { ok: true, running: false, listener: false, firewall: firewall, routing: false };

	let running = system(['/etc/init.d/sing-box', 'running']) == 0;
	let listener = tproxy_listening();
	for (let waited = 0; !listener && waited < (wait_seconds || 0); waited++) {
		system(['/bin/sleep', '1']);
		listener = tproxy_listening();
	}
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

function validate_candidate(outbounds, rules, final, clients, proxying) {
	let lan = lan_device();
	// A redirect without an interface condition would capture traffic arriving
	// from the WAN, so an unanswered ubus has to fail the apply outright.
	if (!lan)
		return result_error('Не удалось определить LAN-интерфейс через ubus', '', 'startup_error');

	let address_of = {};
	for (let client in clients)
		address_of[client.mac] = client.ip;
	let guarded = [];
	for (let mac in guarded_macs(rules))
		if (address_of[mac])
			push(guarded, address_of[mac]);

	mkdir('/etc/zarap');
	chmod('/etc/zarap', 0700);
	let sing_box = sprintf('%J', sing_box_config(outbounds, rules, final, address_of)) + '\n';
	let nft = nft_config(guarded, lan, proxying);
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
	return { ok: true, sing_box: sing_box, nft: nft, guarded: guarded, lan: lan };
}

// firewall4 rebuilds the chains from the generated file but leaves the contents
// of existing sets alone: a set declared without elements does not clear one
// that is already populated. Reloading with an empty client list therefore left
// the previous addresses in the kernel, so a deselected device stayed in the
// kill switch and kept having its traffic sent to a TProxy port nothing was
// listening on. Drive the live sets to the intended contents explicitly.
function sync_live_sets(guarded_ips) {
	let direct = direct_networks();
	let wanted = {
		zarap_guarded_v4: guarded_ips,
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
function live_clients_match(guarded_ips) {
	let live = capture('/usr/sbin/nft list set inet fw4 zarap_guarded_v4').output;
	for (let address in guarded_ips)
		if (index(live, address) < 0)
			return false;
	if (!length(guarded_ips) && index(live, 'elements') >= 0)
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
	// The restored rules keep their kill switch whatever the master switch says.
	let restored_addresses = lease_addresses(), restored_guarded = [];
	for (let mac in guarded_macs(saved_rules()))
		if (restored_addresses[mac])
			push(restored_guarded, restored_addresses[mac]);
	let resynced = sync_live_sets(restored_guarded);
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
	if (listeners && (!length(saved_outbounds()) || index(lc(listeners), 'sing-box') < 0))
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

// Everything both apply and validate have to agree on, in one place: the
// connections, the rules that point at them, the leases the rules depend on and
// the target for whatever no rule matched.
function validate_request(args, enabled) {
	let outbound_result = validate_outbounds(args?.outbounds);
	if (!outbound_result.ok)
		return outbound_result;
	let outbounds = outbound_result.outbounds;

	let tags = {};
	for (let outbound in outbounds)
		tags[outbound.tag] = true;

	let rule_result = validate_rules(args?.rules, tags);
	if (!rule_result.ok)
		return rule_result;
	let rules = rule_result.rules;

	let final = trim('' + (args?.final || 'direct'));
	if (!valid_target(final, tags))
		return input_error('Некорректная цель для остального трафика: ' + (final || '—'));

	// Capturing the whole LAN with nowhere to send it would put the household
	// through sing-box only to hand it straight back out.
	if (enabled && !length(outbounds))
		return input_error('Добавьте хотя бы одно подключение');

	let client_result = validate_clients(args?.clients);
	if (!client_result.ok)
		return client_result;

	// A rule names a MAC; the address comes from the static lease, so every
	// device under a rule has to have one.
	let offered = {};
	for (let client in client_result.clients)
		offered[client.mac] = true;
	for (let mac in guarded_macs(rules))
		if (!offered[mac])
			return input_error('Для устройства ' + mac + ' не указан статический IPv4-адрес');

	client_result = resolve_static_leases(client_result.clients);
	if (!client_result.ok)
		return client_result;

	return { ok: true, outbounds: outbounds, rules: rules, final: final,
		clients: client_result.clients };
}

function apply_configuration(args) {
	let enabled = !!args?.enabled;
	let request = validate_request(args, enabled);
	if (!request.ok)
		return request;

	let conflict = resource_conflict();
	if (!conflict.ok)
		return conflict;

	let candidate = validate_candidate(request.outbounds, request.rules, request.final,
		request.clients, enabled);
	if (!candidate.ok)
		return candidate;
	let uci_candidate = prepare_uci_candidate(request.outbounds, request.rules,
		request.final, enabled, request.clients);
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

	// Devices under a rule stay in the set even with Zarap switched off;
	// releasing one means deleting its rule, which is the only thing that opens
	// its WAN path.
	let live_guarded = candidate.guarded;
	let synced = sync_live_sets(live_guarded);
	if (!synced.ok || !live_clients_match(live_guarded)) {
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

	return { ok: true, enabled: enabled, clients: request.clients, health: health };
}

// The capture covers the whole LAN, so a rule can name any device on it, not
// just a Wi-Fi client. Leases are therefore the base of the list — they know
// about wired hosts — and hostapd only adds what leases cannot tell: whether a
// station is associated right now, and on which radio.
function device_list(rules, final) {
	let devices = {}, leases = static_leases();
	let dynamic_leases = current_dhcp_leases();
	let guarded = guarded_macs(rules);

	function record(mac) {
		if (!devices[mac]) {
			let lease = leases.by_mac[mac] || {};
			let dynamic = dynamic_leases[mac] || {};
			devices[mac] = {
				mac: mac,
				name: lease.name || dynamic.name || ('Устройство ' + mac),
				ip: lease.ip || dynamic.ip || '',
				connected: false,
				wireless: false,
				has_static_lease: !!lease.ip,
				private_mac: is_private_mac(mac),
				guarded: !!guarded[mac],
				resolved_target: resolved_target(mac, rules, final)
			};
		}
		return devices[mac];
	}

	for (let mac in leases.by_mac)
		record(mac);
	for (let mac in dynamic_leases) {
		let device = record(mac);
		// A current lease is not proof of presence, but it is the best the DHCP
		// server can say about a wired host.
		device.connected = true;
	}
	// A device named by a rule belongs in the list even with no lease at all,
	// or the rule would refer to something the page cannot show.
	for (let mac in guarded)
		record(mac);

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
				let device = record(mac);
				device.connected = true;
				device.wireless = true;
				device.network = substr(object, 8);
				device.signal = station?.signal || 0;
			}
		}
		ubus.disconnect();
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
	let outbounds = saved_outbounds(), rules = saved_rules(), final = saved_final();
	let configured = length(outbounds) > 0;
	let health = check_runtime(enabled);
	let state = 'disabled', message = 'Zarap выключен';
	let held = !enabled && length(guarded_macs(rules)) > 0;
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
		message = 'Zarap выключен. Устройства с правилами остаются без выхода в интернет: kill switch не пускает их напрямую. Удалите правило, чтобы вернуть устройству прямой доступ';
	}

	let in_use = {};
	if (final != 'direct' && final != 'block')
		in_use[final] = true;
	for (let rule in rules)
		if (rule.target != 'direct' && rule.target != 'block')
			in_use[rule.target] = true;

	let listed = [];
	for (let outbound in outbounds)
		push(listed, {
			tag: outbound.tag,
			label: outbound.label,
			masked_link: masked_link(outbound),
			in_use: !!in_use[outbound.tag]
		});

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
		outbounds: listed,
		rules: rules,
		final: final,
		capture: { interface: lan_device(), active: enabled && health.listener },
		devices: device_list(rules, final)
	};
}

function logs() {
	// Every connection, not just the first: missing one would put the uuid of a
	// second proxy into the log the user copies out.
	let secrets = [];
	for (let outbound in saved_outbounds())
		for (let key in ['uuid', 'public_key', 'short_id'])
			if (outbound[key])
				push(secrets, outbound[key]);
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
		args: { outbounds: [], rules: [], clients: [], final: '' },
		call: function(request) {
			let checked = validate_request(request.args || {}, true);
			if (!checked.ok) return checked;
			let conflict = resource_conflict();
			if (!conflict.ok) return conflict;
			let candidate = validate_candidate(checked.outbounds, checked.rules,
				checked.final, checked.clients, true);
			if (!candidate.ok) return candidate;
			let uci_candidate = prepare_uci_candidate(checked.outbounds, checked.rules,
				checked.final, true, checked.clients);
			unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK); cleanup_uci_candidate();
			if (!uci_candidate.ok) return uci_candidate;
			return {
				ok: true,
				outbounds: length(checked.outbounds),
				rules: length(checked.rules),
				clients: length(checked.clients),
				capture: candidate.lan
			};
		}
	},
	apply: {
		args: { enabled: true, outbounds: [], rules: [], clients: [], final: '' },
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
