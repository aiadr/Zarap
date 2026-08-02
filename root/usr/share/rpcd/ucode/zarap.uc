#!/usr/bin/env ucode

'use strict';

import { access, chmod, mkdir, open, popen, readfile, rename, unlink, writefile } from 'fs';
import { urldecode, urldecode_params } from 'luci.http';
import { connect } from 'ubus';
import { cursor } from 'uci';

const CONFIG = '/etc/zarap/sing-box.json';
const CONFIG_TMP = '/tmp/zarap-sing-box.json';
const NFT_CONFIG = '/etc/nftables.d/90-zarap.nft';
const NFT_TMP = '/tmp/zarap-nft.conf';
const NFT_CHECK = '/tmp/zarap-nft-check.conf';
const COMPONENTS = { 'luci-app-zarap': true, 'sing-box': true };
const LOCK_FILE = '/var/lock/zarap.lock';

function result_error(message, details) {
	return { ok: false, error: message, details: details || '' };
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
	if (!match(link, /^vless:\/\//))
		return result_error('Ссылка должна начинаться с vless://');

	let fragment_at = index(link, '#');
	if (fragment_at >= 0)
		link = substr(link, 0, fragment_at);

	let query_at = index(link, '?');
	let authority = query_at >= 0 ? substr(link, 8, query_at - 8) : substr(link, 8);
	let query = query_at >= 0 ? substr(link, query_at + 1) : '';
	let at = rindex(authority, '@');
	if (at <= 0)
		return result_error('В ссылке отсутствуют UUID или адрес сервера');

	let uuid = lc(urldecode(substr(authority, 0, at)) || '');
	let endpoint = substr(authority, at + 1);
	let server, port_text;

	if (substr(endpoint, 0, 1) == '[') {
		let closing = index(endpoint, ']');
		if (closing < 2 || substr(endpoint, closing + 1, 1) != ':')
			return result_error('Некорректный IPv6-адрес сервера');
		server = substr(endpoint, 1, closing - 1);
		port_text = substr(endpoint, closing + 2);
	}
	else {
		let colon = rindex(endpoint, ':');
		if (colon <= 0)
			return result_error('В ссылке отсутствует порт сервера');
		server = urldecode(substr(endpoint, 0, colon)) || '';
		port_text = substr(endpoint, colon + 1);
	}

	let port = int(port_text);
	if (!match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/))
		return result_error('Некорректный UUID');
	if (!match(server, /^[A-Za-z0-9._:-]+$/))
		return result_error('Некорректный адрес сервера');
	if (!match(port_text, /^[0-9]+$/) || port < 1 || port > 65535)
		return result_error('Порт сервера должен быть от 1 до 65535');

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
		return result_error('MVP поддерживает только VLESS Reality');
	if (transport != 'tcp')
		return result_error('MVP поддерживает только транспорт TCP');
	if (flow != '' && flow != 'xtls-rprx-vision')
		return result_error('Поддерживается только flow xtls-rprx-vision');
	if (encryption != '' && encryption != 'none')
		return result_error('Для VLESS параметр encryption должен быть none');
	if (!match(sni, /^[A-Za-z0-9.-]+$/))
		return result_error('В Reality-ссылке отсутствует корректный SNI');
	if (!match(public_key, /^[A-Za-z0-9_-]{32,64}$/))
		return result_error('В Reality-ссылке отсутствует корректный публичный ключ');
	if (short_id != '' && !match(short_id, /^[0-9A-Fa-f]{2,32}$/))
		return result_error('Short ID должен быть чётной шестнадцатеричной строкой');
	if (length(short_id) % 2 != 0)
		return result_error('Short ID должен содержать чётное число символов');
	if (!match(fingerprint, /^[A-Za-z0-9_-]+$/))
		return result_error('Некорректный fingerprint');

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
		return result_error('Список устройств имеет неверный формат');

	let result = [], seen_mac = {}, seen_ip = {};
	for (let client in clients) {
		let mac = normalize_mac(client?.mac);
		let ip = trim('' + (client?.ip || ''));
		let name = trim('' + (client?.name || ''));

		if (!mac)
			return result_error('У одного из устройств некорректный MAC-адрес');
		if (is_private_mac(mac))
			return result_error('Устройство ' + mac + ' использует приватный MAC. Отключите рандомизацию MAC для этой Wi-Fi-сети.');
		if (!valid_ipv4(ip))
			return result_error('Для устройства ' + mac + ' нужен корректный статический IPv4-адрес');
		if (seen_mac[mac] || seen_ip[ip])
			return result_error('MAC- и IPv4-адреса выбранных устройств не должны повторяться');
		if (length(name) > 63 || (name != '' && !match(name, /^[A-Za-z0-9А-Яа-яЁё_. -]+$/)))
			return result_error('Имя устройства содержит недопустимые символы');

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
			if (cidr)
				push(v4, cidr);
		}
		for (let item in (lan['ipv6-prefix'] || []))
			if (match(item?.address || '', /^[0-9A-Fa-f:]+$/) && int(item?.mask) >= 0 && int(item?.mask) <= 128)
				push(v6, item.address + '/' + int(item.mask));
		ubus.disconnect();
	}

	return { v4: v4, v6: v6 };
}

function nft_set(name, type_name, flags, elements) {
	let text = 'set ' + name + ' {\n\ttype ' + type_name + '\n';
	if (flags)
		text += '\tflags ' + flags + '\n';
	if (length(elements))
		text += '\telements = { ' + join(', ', elements) + ' }\n';
	return text + '}\n\n';
}

function nft_config(clients, listen_port) {
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
	let leases = static_leases(), result = [];
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
			return result_error('IPv4-адрес ' + client.ip + ' уже закреплён за ' + conflict.mac);
		if (!ipv4_in_lan(client.ip))
			return result_error('IPv4-адрес ' + client.ip + ' не входит в LAN-подсеть');
		push(result, {
			mac: client.mac, ip: client.ip, name: client.name,
			has_static_lease: false
		});
	}
	return { ok: true, clients: result };
}

function save_uci(parsed, enabled, clients) {
	let uci = cursor();
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
	if (!uci.commit('zarap'))
		return false;

	uci.load('dhcp');
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
	if (!uci.commit('dhcp'))
		return false;

	uci.load('sing-box');
	uci.set('sing-box', 'main', 'sing-box');
	uci.set('sing-box', 'main', 'enabled', enabled ? '1' : '0');
	uci.set('sing-box', 'main', 'user', 'root');
	uci.set('sing-box', 'main', 'conffile', CONFIG);
	uci.set('sing-box', 'main', 'workdir', '/tmp/zarap');
	return !!uci.commit('sing-box');
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

function rollback(backups) {
	for (let path, content in backups) {
		if (content == null)
			unlink(path);
		else
			writefile(path, content);
	}
	chmod('/etc/config/zarap', 0600);
	unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
	system(['/etc/init.d/firewall', 'reload']);
	system(['/etc/init.d/dnsmasq', 'restart']);
	system(['/etc/init.d/zarap', 'restart']);
	system(['/etc/init.d/sing-box', 'restart']);
}

function resource_conflict() {
	let listeners = capture('/usr/sbin/ss -H -lntup sport = :7893').output;
	if (listeners && index(lc(listeners), 'sing-box') < 0)
		return result_error('Порт 7893 уже занят другим процессом');

	let routes = capture('/sbin/ip -4 route show table 2022').output;
	if (routes && !match(routes, /^local (default|0\.0\.0\.0\/0) dev lo/))
		return result_error('Таблица маршрутизации 2022 уже используется другой конфигурацией');

	let rules = capture('/sbin/ip -4 rule show').output;
	for (let line in split(rules, '\n'))
		if (index(line, 'fwmark 0x5a52') >= 0 && index(line, 'lookup 2022') < 0)
			return result_error('Packet mark 0x5a52 уже используется другой таблицей маршрутизации');

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
			return result_error('Для первоначальной настройки вставьте VLESS Reality-ссылку');
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

	mkdir('/etc/zarap');
	chmod('/etc/zarap', 0700);
	let sing_box = sprintf('%J', sing_box_config(parsed_result.config, 7893)) + '\n';
	let enabled = !!args?.enabled;
	let nft = nft_config(enabled ? client_result.clients : [], 7893);
	writefile(CONFIG_TMP, sing_box);
	chmod(CONFIG_TMP, 0600);
	writefile(NFT_TMP, nft);
	writefile(NFT_CHECK, 'table inet zarap_check {\n' + nft + '}\n');

	if (system(['/usr/bin/sing-box', 'check', '-c', CONFIG_TMP]) != 0) {
		unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
		return result_error('sing-box отклонил сгенерированную конфигурацию');
	}
	if (system(['/usr/sbin/nft', '-c', '-f', NFT_CHECK]) != 0) {
		unlink(CONFIG_TMP); unlink(NFT_TMP); unlink(NFT_CHECK);
		return result_error('nftables отклонил сгенерированные правила');
	}

	let backups = {};
	for (let path in ['/etc/config/zarap', '/etc/config/dhcp', '/etc/config/sing-box', CONFIG, NFT_CONFIG])
		backups[path] = readfile(path);
	if (backups[CONFIG] != null) {
		writefile(CONFIG + '.bak', backups[CONFIG]);
		chmod(CONFIG + '.bak', 0600);
	}

	if (!save_uci(parsed_result.config, enabled, client_result.clients)) {
		rollback(backups);
		return result_error('Не удалось сохранить конфигурацию UCI');
	}
	chmod('/etc/config/zarap', 0600);

	if (!rename(CONFIG_TMP, CONFIG) || !rename(NFT_TMP, NFT_CONFIG)) {
		rollback(backups);
		return result_error('Не удалось активировать сгенерированные файлы');
	}
	chmod(CONFIG, 0600);
	unlink(NFT_CHECK);

	if (system(['/etc/init.d/firewall', 'reload']) != 0) {
		rollback(backups);
		return result_error('firewall4 не принял правила Zarap; восстановлена предыдущая конфигурация');
	}
	system(['/etc/init.d/dnsmasq', 'restart']);
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
		rollback(backups);
		return result_error('Не удалось запустить Zarap; восстановлена предыдущая конфигурация');
	}

	return { ok: true, enabled: enabled, clients: client_result.clients };
}

function device_list() {
	let devices = {}, selected = {}, leases = static_leases();
	for (let client in read_clients())
		selected[client.mac] = client;

	let ubus = connect();
	if (ubus) {
		let hints = ubus.call('luci-rpc', 'getHostHints') || {};
		let wireless = ubus.call('network.wireless', 'status') || {};
		for (let radio in wireless)
			for (let iface in (wireless[radio]?.interfaces || [])) {
				if (iface?.config?.mode && iface.config.mode != 'ap')
					continue;
				let ifname = iface?.ifname;
				if (!ifname) continue;
				let info = ubus.call('iwinfo', 'info', { device: ifname }) || {};
				let assoc = ubus.call('iwinfo', 'assoclist', { device: ifname }) || {};
				for (let station in (assoc.results || [])) {
					let mac = normalize_mac(station?.mac);
					if (!mac) continue;
					let hint = hints[mac] || {};
					let lease = leases.by_mac[mac] || {};
					devices[mac] = {
						mac: mac,
						name: lease.name || hint.name || selected[mac]?.name || ('Устройство ' + mac),
						ip: lease.ip || hint.ipaddrs?.[0] || selected[mac]?.ip || '',
						connected: true,
						wireless: true,
						network: info.ssid || '',
						signal: station.signal || 0,
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

function status() {
	let uci = cursor();
	uci.load('zarap');
	let enabled = uci.get('zarap', 'main', 'enabled') == '1';
	let configured = !!uci.get('zarap', 'main', 'server');
	let running = system(['/etc/init.d/sing-box', 'running']) == 0;
	let firewall = system('/usr/sbin/nft list chain inet fw4 zarap_killswitch_forward >/dev/null 2>&1') == 0;
	let routing = system('/sbin/ip -4 rule show | grep -q "fwmark 0x5a52.*lookup 2022"') == 0;

	return {
		ok: true,
		enabled: enabled,
		configured: configured,
		running: running,
		firewall: firewall,
		routing: routing,
		server: uci.get('zarap', 'main', 'server') || '',
		server_port: int(uci.get('zarap', 'main', 'server_port') || 0),
		server_name: uci.get('zarap', 'main', 'server_name') || '',
		fingerprint: uci.get('zarap', 'main', 'fingerprint') || '',
		clients: read_clients()
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
	return { ok: true, logs: output };
}

function package_version(name) {
	let found = capture('/sbin/apk info -v ' + name).output;
	return split(found, '\n')[0] || '';
}

function updates(refresh) {
	let refresh_code = 0;
	if (refresh)
		refresh_code = system(['/sbin/apk', 'update']);
	let upgradeable = capture('/sbin/apk list --upgradable').output;
	let components = {};
	for (let name in keys(COMPONENTS)) {
		let line = '';
		for (let candidate in split(upgradeable, '\n'))
			if (match(candidate, regexp('^' + name + '-')))
				line = candidate;
		components[name] = {
			installed: package_version(name),
			update_available: refresh && line != '',
			candidate: line
		};
	}
	return { ok: refresh_code == 0, refresh_code: refresh_code, components: components };
}

function update_component(name) {
	if (!COMPONENTS[name])
		return result_error('Обновление этого пакета запрещено');

	let current = status();
	if (current.enabled && !current.firewall)
		return result_error('Обновление запрещено: kill switch не активен');

	for (let path in ['/etc/config/zarap', CONFIG, NFT_CONFIG]) {
		let content = readfile(path);
		if (content != null) {
			writefile(path + '.bak', content);
			chmod(path + '.bak', 0600);
		}
	}

	if (name == 'sing-box')
		system(['/etc/init.d/sing-box', 'stop']);

	let code = system(['/sbin/apk', 'add', '--upgrade', name]);
	if (code != 0)
		return result_error('apk не смог обновить ' + name + '; kill switch оставлен активным');

	if (access(CONFIG) && system(['/usr/bin/sing-box', 'check', '-c', CONFIG]) != 0)
		return result_error('Новая версия sing-box не принимает текущий конфиг; сервис оставлен остановленным');

	if (system(['/etc/init.d/firewall', 'reload']) != 0)
		return result_error('После обновления firewall4 отклонил правила Zarap');

	if (current.enabled) {
		if (system(['/etc/init.d/zarap', 'restart']) != 0 || system(['/etc/init.d/sing-box', 'restart']) != 0)
			return result_error('Пакет обновлён, но сервис не запустился; kill switch оставлен активным');
		if (system(['/etc/init.d/sing-box', 'running']) != 0)
			return result_error('Пакет обновлён, но процесс sing-box не работает; kill switch оставлен активным');
	}

	return { ok: true, component: name };
}

const methods = {
	status: { call: function() { return status(); } },
	devices: { call: function() { return { ok: true, devices: device_list() }; } },
	validate: {
		args: { link: 'string', clients: [] },
		call: function(request) {
			let parsed = parse_vless(request.args?.link);
			if (!parsed.ok) return parsed;
			let clients = validate_clients(request.args?.clients);
			if (!clients.ok) return clients;
			return { ok: true, server: parsed.config.server, server_name: parsed.config.server_name, clients: length(clients.clients) };
		}
	},
	apply: {
		args: { link: 'string', enabled: 'bool', clients: [] },
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
			return code == 0 ? { ok: true } : result_error('Не удалось перезапустить Zarap');
		}
	},
	stop: {
		call: function() {
			let code = system(['/etc/init.d/sing-box', 'stop']);
			return code == 0 ? { ok: true } : result_error('Не удалось остановить Zarap');
		}
	},
	logs: { call: function() { return logs(); } },
	updates: {
		args: { refresh: 'bool' },
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
		args: { name: 'string' },
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
