import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftConstants, liftMany, readBackend, runUcode, runUcodeJson } from './ucode_helper.mjs';

const OUT_1 = {
	tag: 'out_1',
	server: 'nl.example.test',
	server_port: 443,
	uuid: '123e4567-e89b-42d3-a456-426614174000',
	flow: 'xtls-rprx-vision',
	server_name: 'cdn.example.test',
	public_key: '0123456789abcdefghijklmnopqrstuvwxyzABCDE',
	short_id: 'a1b2',
	fingerprint: 'chrome'
};

const OUT_2 = { ...OUT_1, tag: 'out_2', server: 'de.example.test', flow: '', short_id: '' };
const OUT_ADDR = { ...OUT_1, tag: 'out_1', server: '203.0.113.10' };
const OUT_ADDR6 = { ...OUT_1, tag: 'out_1', server: '2001:db8::1' };

const ADDRESSES = {
	'00:11:22:33:44:55': '192.168.1.50',
	'AA:BB:CC:DD:EE:FF': '192.168.1.51',
	'10:20:30:40:50:60': '192.168.1.61'
};

const ucode = findUcode();

describe('route_mapping', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const constants = liftConstants(source, [
		'const CAPTURE_PORT', 'const INBOUND_TAG', 'const RESERVED_TAGS',
		'const DNS_TAG', 'const DNS_PORT', 'const DNS_OUT_TAG',
		'const DNS_UPSTREAM', 'const BOOTSTRAP_TAG', 'const BOOTSTRAP_DEFAULT',
		'const BOOTSTRAP_SCHEMES', 'const TUNNEL_DEFAULT'
	]);
	const prelude = `${constants}\n${liftMany(source, [
		'valid_outbound_tag', 'valid_ipv4', 'is_domain', 'result_error',
		'input_error', 'parse_resolver', 'xray_dns_server', 'parse_bootstrap',
		'parse_tunnel_dns', 'outbound_json', 'dns_routes', 'dns_domain_tags',
		'xray_domains', 'url_hostname', 'geodata_cron', 'asset_filename',
		'ruleset_plan', 'rule_jsons', 'xray_config'
	])}`;

	function assetFile(url) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', asset_filename(${JSON.stringify(url)}));\n`);
	}

	function generate(outbounds, rules, final, {
		addresses = ADDRESSES,
		rulesets = [],
		rulesetDetour = 'direct',
		rulesetInterval = '1d',
		bootstrap = '',
		resolveAll = false,
		tunnelDns = '',
		skipAssets = null
	} = {}) {
		return runUcodeJson(
			ucode,
			`${prelude}\nprintf('%J', xray_config(${JSON.stringify(outbounds)}, ${JSON.stringify(rules)}, ${JSON.stringify(final)}, ${JSON.stringify(addresses)}, ${JSON.stringify(rulesets)}, ${JSON.stringify(rulesetDetour)}, ${JSON.stringify(bootstrap)}, ${resolveAll ? 'true' : 'false'}, ${JSON.stringify(tunnelDns)}, ${JSON.stringify(skipAssets)}, ${JSON.stringify(rulesetInterval)}));\n`
		);
	}

	const tags = (config) => config.outbounds.map((o) => o.tag);
	const tproxyRules = (config) => config.routing.rules.filter(
		(r) => Array.isArray(r.inboundTag) && r.inboundTag.includes('zarap-tproxy')
	);

	function resolveTargets(rules, final, macs) {
		const body = liftMany(source, ['guarded_macs', 'conditional_rule', 'device_routing']);
		const out = runUcode(
			ucode,
			`${body}\nfor (let mac in ${JSON.stringify(macs)}) printf('%s ', device_routing(mac, ${JSON.stringify(rules)}, ${JSON.stringify(final)}).target);\n`
		);
		return out.trim().split(/\s+/);
	}

	function deviceRouting(rules, final, mac) {
		const body = liftMany(source, ['conditional_rule', 'device_routing']);
		return runUcodeJson(
			ucode,
			`${body}\nprintf('%J', device_routing(${JSON.stringify(mac)}, ${JSON.stringify(rules)}, ${JSON.stringify(final)}));\n`
		);
	}

	function guarded(rules) {
		const body = liftMany(source, ['guarded_macs']);
		return runUcodeJson(
			ucode,
			`${body}\nlet macs = [];\nfor (let mac in guarded_macs(${JSON.stringify(rules)})) push(macs, mac);\nprintf('%J', sort(macs));\n`
		);
	}

	test('capture without any policy emits only trailing final rule', () => {
		const config = generate([OUT_1], [], 'direct');
		assert.deepEqual(config.routing.rules, [
			{ type: 'field', inboundTag: ['zarap-tproxy'], outboundTag: 'direct' }
		]);
		assert.equal(config.routing.domainStrategy, 'AsIs');
		assert.deepEqual(tags(config), ['out_1', 'direct']);
		assert.equal(config.outbounds[1].protocol, 'freedom');
	});

	test('outbound carries the reality fields and domainStrategy for domain servers', () => {
		const outbound = generate([OUT_1], [], 'direct').outbounds[0];
		assert.equal(outbound.protocol, 'vless');
		assert.equal(outbound.settings.vnext[0].address, 'nl.example.test');
		assert.equal(outbound.settings.vnext[0].port, 443);
		assert.equal(outbound.settings.vnext[0].users[0].id, OUT_1.uuid);
		assert.equal(outbound.settings.vnext[0].users[0].encryption, 'none');
		assert.equal(outbound.settings.vnext[0].users[0].flow, 'xtls-rprx-vision');
		assert.equal(outbound.streamSettings.network, 'tcp');
		assert.equal(outbound.streamSettings.security, 'reality');
		assert.equal(outbound.streamSettings.realitySettings.serverName, 'cdn.example.test');
		assert.equal(outbound.streamSettings.realitySettings.shortId, 'a1b2');
		assert.equal(outbound.streamSettings.realitySettings.fingerprint, 'chrome');
		assert.deepEqual(outbound.streamSettings.sockopt, { domainStrategy: 'UseIPv4' });

		const ipOutbound = generate([OUT_ADDR], [], 'direct').outbounds[0];
		assert.equal('sockopt' in ipOutbound.streamSettings, false);
	});

	test('empty flow and short_id are omitted', () => {
		const outbound = generate([OUT_2], [], 'direct').outbounds[0];
		assert.equal('flow' in outbound.settings.vnext[0].users[0], false);
		assert.equal('shortId' in outbound.streamSettings.realitySettings, false);
	});

	test('rule order follows section order and appends final catch-all', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], target: 'out_1' },
			{ clients: ['10:20:30:40:50:60'], target: 'block' },
			{ clients: ['AA:BB:CC:DD:EE:FF'], target: 'direct' }
		];
		const config = generate([OUT_1], rules, 'direct');
		assert.deepEqual(config.routing.rules.map((r) => r.outboundTag), ['out_1', 'block', 'direct', 'direct']);
		assert.ok(tags(config).includes('block'));
		assert.equal(config.outbounds.find((o) => o.tag === 'block').protocol, 'blackhole');
	});

	test('direct and block outbounds are declared only when referenced', () => {
		const proxied = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'out_1');
		assert.deepEqual(tags(proxied), ['out_1']);

		const byRule = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'direct' }], 'out_1');
		assert.deepEqual(tags(byRule), ['out_1', 'direct']);

		const byBlock = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'block' }], 'out_1');
		assert.deepEqual(tags(byBlock), ['out_1', 'block']);
	});

	test('final block appends a catch-all pointing to block', () => {
		const config = generate(
			[OUT_1, OUT_2],
			[{ clients: ['00:11:22:33:44:55'], target: 'out_2' }],
			'block'
		);
		const last = config.routing.rules.at(-1);
		assert.deepEqual(last, { type: 'field', inboundTag: ['zarap-tproxy'], outboundTag: 'block' });
		assert.ok(tags(config).includes('block'));
	});

	test('several devices in one rule give one element', () => {
		const rules = [{ clients: ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF'], target: 'out_1' }];
		const emitted = tproxyRules(generate([OUT_1], rules, 'direct'));
		assert.equal(emitted.length, 2);
		assert.deepEqual(emitted[0].source, ['192.168.1.50/32', '192.168.1.51/32']);
	});

	test('device is resolved through its lease', () => {
		const rules = [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }];
		const emitted = tproxyRules(generate([OUT_1], rules, 'direct', {
			addresses: { '00:11:22:33:44:55': '10.0.0.7' }
		}));
		assert.deepEqual(emitted[0].source, ['10.0.0.7/32']);
	});

	test('inbound is a dokodemo-door tproxy listener', () => {
		const inbounds = generate([OUT_1], [], 'direct').inbounds;
		assert.equal(inbounds.length, 1);
		assert.equal(inbounds[0].protocol, 'dokodemo-door');
		assert.equal(inbounds[0].tag, 'zarap-tproxy');
		assert.equal(inbounds[0].listen, '0.0.0.0');
		assert.equal(inbounds[0].port, 7893);
		assert.deepEqual(inbounds[0].settings, { network: 'tcp,udp', followRedirect: true });
		assert.deepEqual(inbounds[0].streamSettings, { sockopt: { tproxy: 'tproxy' } });
		assert.equal('sniffing' in inbounds[0], false);
	});

	test('a domain and a range become a group with one target', () => {
		const rules = [{
			clients: ['00:11:22:33:44:55'],
			domains: ['youtube.com'],
			ip_cidr: ['149.154.160.0/20'],
			ports: ['443'],
			target: 'out_1'
		}];
		const config = generate([OUT_1], rules, 'direct');
		assert.deepEqual(config.inbounds[0].sniffing, {
			enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true
		});
		const group = tproxyRules(config).slice(0, -1);
		assert.equal(group.length, 2);
		assert.deepEqual(group[0].domain, ['domain:youtube.com']);
		assert.deepEqual(group[1].ip, ['149.154.160.0/20']);
		for (const element of group) {
			assert.deepEqual(element.source, ['192.168.1.50/32']);
			assert.equal(element.port, '443');
			assert.equal(element.outboundTag, 'out_1');
		}
	});

	test('domain maps apex+subdomains to domain: and leading-dot to regexp:', () => {
		const rules = [{ domains: ['youtube.com', '.googlevideo.com'], target: 'out_1' }];
		const element = tproxyRules(generate([OUT_1], rules, 'direct'))[0];
		assert.deepEqual(element.domain, ['domain:youtube.com', 'regexp:\\.googlevideo\\.com$']);
	});

	test('sniffing is enabled only for domains or geosite rulesets', () => {
		const ipOnly = generate([OUT_1], [{ ip_cidr: ['10.0.0.0/8'], target: 'out_1' }], 'direct');
		assert.equal('sniffing' in ipOnly.inbounds[0], false);

		const geoipOnly = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets: [{ tag: 'rs_1', url: 'https://e.org/geoip.dat', kind: 'geoip', category: 'telegram' }]
		});
		assert.equal('sniffing' in geoipOnly.inbounds[0], false);

		const geosite = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets: [{ tag: 'rs_1', url: 'https://e.org/geosite.dat', kind: 'geosite', category: 'youtube' }]
		});
		assert.equal(geosite.inbounds[0].sniffing.enabled, true);
		assert.equal(geosite.inbounds[0].sniffing.routeOnly, true);
	});

	test('ports and ranges become comma-separated xray port string', () => {
		const rules = [{ clients: [], ports: ['443', '1000:2000'], network: 'udp', target: 'block' }];
		const emitted = tproxyRules(generate([OUT_1], rules, 'direct'))[0];
		assert.equal(emitted.port, '443,1000-2000');
		assert.equal(emitted.network, 'udp');
		assert.equal(emitted.outboundTag, 'block');
	});

	test('a rule without devices carries no source', () => {
		const rules = [{ clients: [], ip_cidr: ['10.0.0.0/8'], target: 'direct' }];
		const emitted = tproxyRules(generate([OUT_1], rules, 'out_1'))[0];
		assert.equal('source' in emitted, false);
	});

	test('rulesets key .dat by URL hash, deduplicate by URL, and follow the global schedule', () => {
		const geositeFile = assetFile('https://example.org/geosite.dat');
		const geoipFile = assetFile('https://example.org/geoip.dat');
		assert.match(geositeFile, /^dat_[0-9a-f]{16}\.dat$/);
		assert.notEqual(geositeFile, geoipFile);

		const rulesets = [
			{ tag: 'rs_1', label: 'YouTube', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'youtube' },
			{ tag: 'rs_2', label: 'OpenAI', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'openai' },
			{ tag: 'rs_3', label: 'Telegram IP', url: 'https://example.org/geoip.dat', kind: 'geoip', category: 'telegram' }
		];
		const config = generate([OUT_1], [{ rule_sets: ['rs_1', 'rs_2', 'rs_3'], target: 'out_1' }], 'direct', {
			rulesets, rulesetDetour: 'out_1', rulesetInterval: '12h'
		});
		assert.deepEqual(config.geodata, {
			assets: [
				{ url: 'https://example.org/geosite.dat', file: geositeFile },
				{ url: 'https://example.org/geoip.dat', file: geoipFile }
			],
			cron: '0 */12 * * *',
			outbound: 'out_1'
		});
		const group = tproxyRules(config).slice(0, -1);
		assert.equal(group.length, 2);
		assert.deepEqual(group[0].domain, [`ext:${geositeFile}:youtube`, `ext:${geositeFile}:openai`]);
		assert.deepEqual(group[1].ip, [`ext:${geoipFile}:telegram`]);

		const disabled = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets, rulesetDetour: 'out_1', rulesetInterval: ''
		});
		assert.equal('geodata' in disabled, false);
	});

	test('reusing tag rs_1 with a new URL produces a distinct .dat filename', () => {
		const first = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets: [{ tag: 'rs_1', url: 'https://a.example/geosite.dat', kind: 'geosite', category: 'youtube' }]
		});
		const second = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets: [{ tag: 'rs_1', url: 'https://b.example/geosite.dat', kind: 'geosite', category: 'youtube' }]
		});
		assert.notEqual(first.geodata.assets[0].file, second.geodata.assets[0].file);
	});

	test('skip_assets omits not-yet-downloaded ext: references and geodata entries during dry-run validation', () => {
		const geositeFile = assetFile('https://example.org/geosite.dat');
		const rulesets = [
			{ tag: 'rs_1', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'youtube' }
		];
		const config = generate([OUT_1], [{ domains: ['example.com'], rule_sets: ['rs_1'], target: 'out_1' }], 'direct', {
			rulesets, resolveAll: true, bootstrap: 'https://1.1.1.1/dns-query', skipAssets: { [geositeFile]: true }
		});
		assert.deepEqual(tproxyRules(config)[0].domain, ['domain:example.com']);
		const tunnelDns = config.dns.servers.find((s) => s.tag === 'dns_out_1');
		assert.deepEqual(tunnelDns.domains, ['domain:example.com']);
		assert.equal('geodata' in config, false);
	});

	test('an unused rule set emits no geodata block', () => {
		const rulesets = [{ tag: 'rs_1', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'ads' }];
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct', {
			rulesets
		});
		assert.equal('geodata' in config, false);
	});

	test('named domains resolve through their own outbound listener without leaks or loops', () => {
		const config = generate([OUT_1, OUT_2], [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['example.com'], target: 'out_2' }
		], 'direct');

		assert.equal(config.dns.queryStrategy, 'UseIPv4');
		assert.equal(config.dns.disableFallbackIfMatch, true);
		// Server-domain bootstrap shield comes FIRST with skipFallback + finalQuery
		assert.deepEqual(config.dns.servers[0], {
			address: 'localhost',
			domains: ['full:nl.example.test', 'full:de.example.test'],
			skipFallback: true,
			finalQuery: true
		});
		// First tunnel DNS serves out_1 domains and acts as sole fallback
		assert.deepEqual(config.dns.servers[1], {
			address: 'https://1.1.1.1/dns-query',
			tag: 'dns_out_1',
			domains: ['domain:youtube.com']
		});
		// Second tunnel DNS is strict so it never falls back to dns_out_1 or bootstrap
		assert.deepEqual(config.dns.servers[2], {
			address: 'https://1.1.1.1/dns-query',
			tag: 'dns_out_2',
			domains: ['domain:example.com'],
			skipFallback: true,
			finalQuery: true
		});

		// Each outbound with named domains gets its own DNS listener (5353, 5354)
		// and its own dns-out bound via dialerProxy to that exact outbound.
		assert.deepEqual(config.inbounds.slice(1), [
			{
				tag: 'zarap-dns',
				listen: '127.0.0.1',
				port: 5353,
				protocol: 'dokodemo-door',
				settings: { address: '1.1.1.1', port: 53, network: 'tcp,udp' }
			},
			{
				tag: 'zarap-dns-out_2',
				listen: '127.0.0.1',
				port: 5354,
				protocol: 'dokodemo-door',
				settings: { address: '1.1.1.1', port: 53, network: 'tcp,udp' }
			}
		]);

		// Internal DNS routing rules sit before any tproxy rule
		assert.deepEqual(config.routing.rules.slice(0, 4), [
			{ type: 'field', inboundTag: ['zarap-dns'], outboundTag: 'dns-out' },
			{ type: 'field', inboundTag: ['zarap-dns-out_2'], outboundTag: 'dns-out-out_2' },
			{ type: 'field', inboundTag: ['dns_out_1'], outboundTag: 'out_1' },
			{ type: 'field', inboundTag: ['dns_out_2'], outboundTag: 'out_2' }
		]);
		assert.deepEqual(config.outbounds.find((o) => o.tag === 'dns-out'), {
			tag: 'dns-out',
			protocol: 'dns',
			settings: {
				rewriteNetwork: 'tcp',
				rewriteAddress: '1.1.1.1',
				rewritePort: 53,
				rules: [
					{ action: 'hijack', qType: '1,28' },
					{ action: 'direct' }
				]
			},
			streamSettings: { sockopt: { dialerProxy: 'out_1' } }
		});
		assert.deepEqual(config.outbounds.find((o) => o.tag === 'dns-out-out_2'), {
			tag: 'dns-out-out_2',
			protocol: 'dns',
			settings: {
				rewriteNetwork: 'tcp',
				rewriteAddress: '1.1.1.1',
				rewritePort: 53,
				rules: [
					{ action: 'hijack', qType: '1,28' },
					{ action: 'direct' }
				]
			},
			streamSettings: { sockopt: { dialerProxy: 'out_2' } }
		});
	});

	test('resolve_all marks every tunnel DNS strict and tunnels non-IP queries without false NOERROR or plaintext downgrade', () => {
		const geositeFile = assetFile('https://e.org/geosite.dat');
		const rulesets = [{ tag: 'rs_1', url: 'https://e.org/geosite.dat', kind: 'geosite', category: 'youtube' }];
		const rules = [{ domains: ['example.com'], rule_sets: ['rs_1'], target: 'out_1' }];

		const off = generate([OUT_1], rules, 'direct', { rulesets });
		assert.deepEqual(off.dns.servers[1].domains, ['domain:example.com']);

		const on = generate([OUT_1], rules, 'direct', {
			rulesets, resolveAll: true, bootstrap: 'https://77.88.8.8/dns-query'
		});
		assert.deepEqual(on.dns.servers, [
			{
				address: 'https+local://77.88.8.8/dns-query',
				domains: ['full:nl.example.test', 'full:e.org'],
				skipFallback: true,
				finalQuery: true
			},
			{
				address: 'https://1.1.1.1/dns-query',
				tag: 'dns_out_1',
				domains: ['domain:example.com', `ext:${geositeFile}:youtube`],
				skipFallback: true,
				finalQuery: true
			},
			{
				address: 'https+local://77.88.8.8/dns-query'
			}
		]);
		assert.deepEqual(on.outbounds.find((o) => o.tag === 'dns-out'), {
			tag: 'dns-out',
			protocol: 'dns',
			settings: {
				rewriteNetwork: 'tcp',
				rewriteAddress: '1.1.1.1',
				rewritePort: 53,
				rules: [
					{ action: 'hijack', qType: '1,28' },
					{ action: 'direct' }
				]
			},
			streamSettings: { sockopt: { dialerProxy: 'out_1' } }
		});
	});

	test('udp bootstrap adds direct routing rule and freedom outbound', () => {
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'out_1', {
			bootstrap: 'udp://192.168.1.1'
		});
		assert.deepEqual(config.dns.servers, [{ address: '192.168.1.1', tag: 'dns_bootstrap' }]);
		assert.deepEqual(config.routing.rules[0], {
			type: 'field', inboundTag: ['dns_bootstrap'], outboundTag: 'direct'
		});
		assert.ok(tags(config).includes('direct'));
	});

	test('a server given by IP asks for no dns block when nothing else needs DNS', () => {
		for (const outbound of [OUT_ADDR, OUT_ADDR6]) {
			const config = generate([outbound], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct');
			assert.equal('dns' in config, false);
		}
	});

	test('a list fetched directly needs bootstrap DNS for its host', () => {
		const rulesets = [{ tag: 'rs_1', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'ads' }];
		const rules = [{ rule_sets: ['rs_1'], target: 'block' }];
		const direct = generate([OUT_ADDR], rules, 'direct', { rulesets });
		assert.deepEqual(direct.dns.servers, [{ address: 'localhost' }]);

		const detoured = generate([OUT_ADDR], rules, 'direct', { rulesets, rulesetDetour: 'out_1' });
		assert.equal('dns' in detoured, false);
	});

	test('the dns listener appears only with tunnel domains or resolve_all', () => {
		const listener = {
			tag: 'zarap-dns',
			listen: '127.0.0.1',
			port: 5353,
			protocol: 'dokodemo-door',
			settings: { address: '1.1.1.1', port: 53, network: 'tcp,udp' }
		};
		const withDomains = generate([OUT_1], [{ domains: ['youtube.com'], target: 'out_1' }], 'direct');
		assert.ok(withDomains.inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)));

		const resolveAllOnly = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct', {
			resolveAll: true, bootstrap: 'https://1.1.1.1/dns-query'
		});
		assert.ok(resolveAllOnly.inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)));

		for (const target of ['direct', 'block']) {
			const plain = generate([OUT_1], [{ domains: ['youtube.com'], target }], 'direct');
			assert.equal(plain.inbounds.some((i) => i.tag === 'zarap-dns'), false);
		}
	});

	test('first matching rule decides where a device goes', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], target: 'out_1' },
			{ clients: ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF'], target: 'block' }
		];
		assert.deepEqual(
			resolveTargets(rules, 'direct', ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF', '10:20:30:40:50:60']),
			['out_1', 'block', 'direct']
		);
	});

	test('a conditional rule does not decide where a device goes', () => {
		const rules = [{ clients: ['00:11:22:33:44:55'], ip_cidr: ['10.0.0.0/8'], target: 'out_1' }];
		assert.deepEqual(deviceRouting(rules, 'direct', '00:11:22:33:44:55'), { target: 'direct', partial: [1] });
	});

	test('a rule naming no device is partial for everyone', () => {
		const rules = [{ clients: [], ports: ['443'], network: 'udp', target: 'block' }];
		assert.deepEqual(deviceRouting(rules, 'out_1', '00:11:22:33:44:55'), { target: 'out_1', partial: [1] });
	});

	test('collecting partial rules stops at the rule that takes it whole', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], ports: ['443'], target: 'out_1' },
			{ clients: ['00:11:22:33:44:55'], target: 'block' },
			{ clients: ['00:11:22:33:44:55'], ip_cidr: ['10.0.0.0/8'], target: 'out_1' }
		];
		assert.deepEqual(deviceRouting(rules, 'direct', '00:11:22:33:44:55'), { target: 'block', partial: [1] });
	});

	test('guarded_macs collects every named device', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], target: 'direct' },
			{ clients: ['AA:BB:CC:DD:EE:FF', '00:11:22:33:44:55'], target: 'block' }
		];
		assert.deepEqual(guarded(rules), ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF']);
	});

	test('a rule limited by destination still guards its device', () => {
		const rules = [{ clients: ['00:11:22:33:44:55'], ip_cidr: ['10.0.0.0/8'], ports: ['443'], target: 'out_1' }];
		assert.deepEqual(guarded(rules), ['00:11:22:33:44:55']);
	});

	test('a rule naming no device guards nobody', () => {
		const rules = [
			{ clients: [], ip_cidr: ['10.0.0.0/8'], target: 'out_1' },
			{ clients: [], ports: ['443'], network: 'udp', target: 'block' }
		];
		assert.deepEqual(guarded(rules), []);
	});

	test('outbound tags are validated', () => {
		const candidates = [
			'out_1', 'out_42', 'direct', 'block', 'dns', 'dns-out', 'main',
			'zarap-tproxy', 'out_', 'proxy', 'Out_1', ''
		];
		const out = runUcode(
			ucode,
			`${prelude}\nfor (let tag in ${JSON.stringify(candidates)}) printf('%s ', valid_outbound_tag(tag));\n`
		);
		assert.deepEqual(out.trim().split(/\s+/), ['true', 'true', ...Array(10).fill('false')]);
	});
});
