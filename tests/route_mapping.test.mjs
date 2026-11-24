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
		'const CACHE_FILE', 'const DNS_TAG', 'const DNS_PORT',
		'const DNS_UPSTREAM', 'const BOOTSTRAP_TAG', 'const BOOTSTRAP_DEFAULT',
		'const BOOTSTRAP_SCHEMES', 'const TUNNEL_DEFAULT'
	]);
	const prelude = `${constants}\n${liftMany(source, [
		'valid_outbound_tag', 'valid_ipv4', 'is_domain', 'result_error',
		'input_error', 'parse_resolver', 'parse_bootstrap', 'parse_tunnel_dns',
		'outbound_json', 'dns_routes', 'domain_json', 'rule_jsons',
		'sing_box_config'
	])}`;

	function generate(outbounds, rules, final, {
		addresses = ADDRESSES,
		rulesets = [],
		rulesetDetour = 'direct',
		bootstrap = '',
		resolveAll = false,
		tunnelDns = ''
	} = {}) {
		return runUcodeJson(
			ucode,
			`${prelude}\nprintf('%J', sing_box_config(${JSON.stringify(outbounds)}, ${JSON.stringify(rules)}, ${JSON.stringify(final)}, ${JSON.stringify(addresses)}, ${JSON.stringify(rulesets)}, ${JSON.stringify(rulesetDetour)}, ${JSON.stringify(bootstrap)}, ${resolveAll ? 'true' : 'false'}, ${JSON.stringify(tunnelDns)}));\n`
		);
	}

	const tags = (config) => config.outbounds.map((o) => o.tag);
	const dnsTags = (config) => (config.dns?.servers || []).map((s) => s.tag);

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

	test('capture without any policy routes nothing', () => {
		const config = generate([OUT_1], [], 'direct');
		assert.deepEqual(config.route.rules, []);
		assert.equal(config.route.final, 'direct');
		assert.deepEqual(tags(config), ['out_1', 'direct']);
	});

	test('outbound carries the reality fields', () => {
		const outbound = generate([OUT_1], [], 'direct').outbounds[0];
		assert.equal(outbound.type, 'vless');
		assert.equal(outbound.server_port, 443);
		assert.equal(outbound.flow, 'xtls-rprx-vision');
		assert.equal(outbound.tls.reality.enabled, true);
		assert.equal(outbound.tls.reality.short_id, 'a1b2');
		assert.equal(outbound.tls.utls.fingerprint, 'chrome');
	});

	test('empty flow and short_id are omitted', () => {
		const outbound = generate([OUT_2], [], 'direct').outbounds[0];
		assert.equal('flow' in outbound, false);
		assert.equal('short_id' in outbound.tls.reality, false);
	});

	test('rule order follows section order', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], target: 'out_1' },
			{ clients: ['10:20:30:40:50:60'], target: 'block' },
			{ clients: ['AA:BB:CC:DD:EE:FF'], target: 'direct' }
		];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.deepEqual(emitted.map((r) => r.outbound || r.action), ['out_1', 'reject', 'direct']);
	});

	test('block becomes a reject action and not an outbound', () => {
		const rules = [{ clients: ['10:20:30:40:50:60'], target: 'block' }];
		const config = generate([OUT_1], rules, 'direct');
		assert.equal(config.route.rules[0].action, 'reject');
		assert.equal('outbound' in config.route.rules[0], false);
		assert.equal(tags(config).includes('block'), false);
	});

	test('direct is declared only when referenced', () => {
		const proxied = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'out_1');
		assert.deepEqual(tags(proxied), ['out_1']);

		const byRule = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'direct' }], 'out_1');
		assert.deepEqual(tags(byRule), ['out_1', 'direct']);

		const byFinal = generate([OUT_1], [], 'direct');
		assert.deepEqual(tags(byFinal), ['out_1', 'direct']);
	});

	test('final block appends a catch-all and keeps a valid tag', () => {
		const config = generate(
			[OUT_1, OUT_2],
			[{ clients: ['00:11:22:33:44:55'], target: 'out_2' }],
			'block'
		);
		const last = config.route.rules.at(-1);
		assert.equal(last.action, 'reject');
		assert.equal('source_ip_cidr' in last, false);
		assert.ok(tags(config).includes(config.route.final));
		assert.equal(config.route.final, 'out_1');
	});

	test('final proxy routes the remainder without extra rules', () => {
		const config = generate([OUT_1], [], 'out_1');
		assert.deepEqual(config.route.rules, []);
		assert.equal(config.route.final, 'out_1');
	});

	test('several devices in one rule give one element', () => {
		const rules = [{ clients: ['00:11:22:33:44:55', 'AA:BB:CC:DD:EE:FF'], target: 'out_1' }];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.equal(emitted.length, 1);
		assert.deepEqual(emitted[0].source_ip_cidr, ['192.168.1.50/32', '192.168.1.51/32']);
	});

	test('device is resolved through its lease', () => {
		const rules = [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }];
		const emitted = generate([OUT_1], rules, 'direct', {
			addresses: { '00:11:22:33:44:55': '10.0.0.7' }
		}).route.rules;
		assert.deepEqual(emitted[0].source_ip_cidr, ['10.0.0.7/32']);
	});

	test('every rule names the inbound', () => {
		const rules = [
			{ clients: ['00:11:22:33:44:55'], target: 'out_1' },
			{ clients: ['10:20:30:40:50:60'], target: 'block' }
		];
		const config = generate([OUT_1], rules, 'block');
		for (const rule of config.route.rules)
			assert.deepEqual(rule.inbound, ['zarap-tproxy']);
	});

	test('inbound is a single tproxy listener', () => {
		const inbounds = generate([OUT_1], [], 'direct').inbounds;
		assert.equal(inbounds.length, 1);
		assert.equal(inbounds[0].type, 'tproxy');
		assert.equal(inbounds[0].tag, 'zarap-tproxy');
		assert.equal(inbounds[0].listen_port, 7893);
	});

	test('a domain and a range become a group with one target', () => {
		const rules = [{
			clients: ['00:11:22:33:44:55'],
			domains: ['youtube.com'],
			ip_cidr: ['149.154.160.0/20'],
			ports: ['443'],
			target: 'out_1'
		}];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.deepEqual(emitted[0], { inbound: ['zarap-dns'], action: 'hijack-dns' });
		assert.deepEqual(emitted[1], { inbound: ['zarap-tproxy'], action: 'sniff' });
		const group = emitted.slice(2);
		assert.equal(group.length, 2);
		assert.deepEqual(group[0].domain, ['youtube.com']);
		assert.deepEqual(group[1].ip_cidr, ['149.154.160.0/20']);
		for (const element of group) {
			assert.deepEqual(element.source_ip_cidr, ['192.168.1.50/32']);
			assert.deepEqual(element.port, [443]);
			assert.equal(element.outbound, 'out_1');
		}
	});

	test('a domain covers the name and everything under it', () => {
		const rules = [{ domains: ['youtube.com', '.googlevideo.com'], target: 'out_1' }];
		const element = generate([OUT_1], rules, 'direct').route.rules[2];
		assert.deepEqual(element.domain, ['youtube.com']);
		assert.deepEqual(element.domain_suffix, ['.youtube.com', '.googlevideo.com']);
	});

	test('sniff is emitted only for domains and before any matching', () => {
		const without = generate([OUT_1], [{ ip_cidr: ['10.0.0.0/8'], target: 'out_1' }], 'direct');
		assert.equal(JSON.stringify(without.route.rules).includes('sniff'), false);

		const emitted = generate([OUT_1], [
			{ clients: ['00:11:22:33:44:55'], target: 'direct' },
			{ domains: ['youtube.com'], target: 'out_1' }
		], 'direct').route.rules;
		const sniff = emitted.map((r, i) => (r.action === 'sniff' ? i : -1)).filter((i) => i >= 0);
		const matching = emitted
			.map((r, i) => (!('action' in r) || r.action === 'reject' ? i : -1))
			.filter((i) => i >= 0);
		assert.equal(sniff.length, 1);
		assert.ok(sniff[0] < Math.min(...matching));
	});

	test('block rejects in every element of the group', () => {
		const rules = [{ domains: ['ads.example'], ip_cidr: ['10.0.0.0/8'], target: 'block' }];
		const group = generate([OUT_1], rules, 'direct').route.rules.slice(1);
		assert.equal(group.length, 2);
		for (const element of group) {
			assert.equal(element.action, 'reject');
			assert.equal('outbound' in element, false);
		}
	});

	test('source range and port meet in one element', () => {
		const rules = [{
			clients: ['00:11:22:33:44:55'],
			ip_cidr: ['149.154.160.0/20'],
			ports: ['443'],
			target: 'out_1'
		}];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.equal(emitted.length, 1);
		assert.deepEqual(emitted[0].ip_cidr, ['149.154.160.0/20']);
		assert.deepEqual(emitted[0].source_ip_cidr, ['192.168.1.50/32']);
		assert.deepEqual(emitted[0].port, [443]);
		assert.equal(emitted[0].outbound, 'out_1');
	});

	test('ports and ranges land in their own fields', () => {
		const rules = [{ clients: [], ports: ['443', '1000:2000'], network: 'udp', target: 'block' }];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.deepEqual(emitted[0].port, [443]);
		assert.deepEqual(emitted[0].port_range, ['1000:2000']);
		assert.deepEqual(emitted[0].network, ['udp']);
		assert.equal(emitted[0].action, 'reject');
	});

	test('a rule without devices carries no source', () => {
		const rules = [{ clients: [], ip_cidr: ['10.0.0.0/8'], target: 'direct' }];
		const emitted = generate([OUT_1], rules, 'out_1').route.rules;
		assert.equal('source_ip_cidr' in emitted[0], false);
	});

	test('an unresolvable device leaves the rule without a source', () => {
		const rules = [{ clients: ['FF:FF:FF:FF:FF:FF'], ip_cidr: ['10.0.0.0/8'], target: 'out_1' }];
		const emitted = generate([OUT_1], rules, 'direct').route.rules;
		assert.equal('source_ip_cidr' in emitted[0], false);
	});

	test('a rule set is declared remote with its detour and schedule', () => {
		const rulesets = [{
			tag: 'rs_1', label: 'Реклама',
			url: 'https://example.org/ads.srs', update_interval: '1d'
		}];
		const config = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'block' }], 'direct', {
			rulesets, rulesetDetour: 'out_1'
		});
		assert.deepEqual(config.route.rule_set, [{
			type: 'remote', tag: 'rs_1', format: 'binary',
			url: 'https://example.org/ads.srs',
			download_detour: 'out_1', update_interval: '1d'
		}]);
		assert.deepEqual(config.experimental.cache_file, { enabled: true, path: '/etc/zarap/cache.db' });
	});

	test('one detour covers every declared set', () => {
		const rulesets = [
			{ tag: 'rs_1', label: '', url: 'https://example.org/a.srs', update_interval: '' },
			{ tag: 'rs_2', label: '', url: 'https://example.org/b.srs', update_interval: '1d' }
		];
		const declared = generate([OUT_1], [{ rule_sets: ['rs_1', 'rs_2'], target: 'block' }], 'direct', {
			rulesets, rulesetDetour: 'out_1'
		}).route.rule_set;
		assert.deepEqual(declared.map((e) => e.download_detour), ['out_1', 'out_1']);
	});

	test('a direct detour is left out being the default', () => {
		const rulesets = [{ tag: 'rs_1', label: '', url: 'https://example.org/a.srs', update_interval: '' }];
		const declared = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'block' }], 'direct', {
			rulesets
		}).route.rule_set[0];
		assert.equal('download_detour' in declared, false);
		assert.equal('update_interval' in declared, false);
	});

	test('an unused rule set is not declared and costs no cache', () => {
		const rulesets = [{ tag: 'rs_1', label: '', url: 'https://example.org/a.srs', update_interval: '' }];
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct', {
			rulesets
		});
		assert.equal('rule_set' in config.route, false);
		assert.equal('experimental' in config, false);
	});

	test('a rule set asks for sniffing too', () => {
		const config = generate([OUT_1], [{ rule_sets: ['rs_1'], target: 'block' }], 'direct', {
			rulesets: [{ tag: 'rs_1', label: '', url: 'https://e.org/a.srs', update_interval: '' }]
		});
		assert.deepEqual(config.route.rules[0], { inbound: ['zarap-tproxy'], action: 'sniff' });
	});

	test('named domains are resolved through the outbound that routes them', () => {
		const config = generate([OUT_1, OUT_2], [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['example.com'], target: 'out_2' }
		], 'direct');
		assert.deepEqual(config.dns.servers, [
			{ type: 'local', tag: 'dns_bootstrap' },
			{ type: 'https', tag: 'dns_out_1', server: '1.1.1.1', detour: 'out_1' },
			{ type: 'https', tag: 'dns_out_2', server: '1.1.1.1', detour: 'out_2' }
		]);
		assert.equal(config.dns.rules[0].server, 'dns_out_1');
		assert.deepEqual(config.dns.rules[0].domain, ['youtube.com']);
		assert.equal(config.dns.strategy, 'ipv4_only');
		assert.equal(config.dns.final, 'dns_out_1');
		assert.equal(config.route.default_domain_resolver, 'dns_bootstrap');
	});

	test('a server named by domain resolves outside the tunnel', () => {
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'out_1');
		assert.equal(config.route.default_domain_resolver, 'dns_bootstrap');
		const bootstrap = config.dns.servers[0];
		assert.deepEqual(bootstrap, { type: 'local', tag: 'dns_bootstrap' });
		assert.equal('detour' in bootstrap, false);
		const dohBoot = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'out_1', {
			bootstrap: 'https://1.1.1.1'
		}).dns.servers[0];
		assert.equal('detour' in dohBoot, false);
		assert.deepEqual(tags(config), ['out_1']);
	});

	test('the bootstrap resolver is the one that was chosen', () => {
		const rules = [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }];
		for (const [value, expected] of [
			['', { type: 'local', tag: 'dns_bootstrap' }],
			['https://1.1.1.1', { type: 'https', tag: 'dns_bootstrap', server: '1.1.1.1' }],
			['udp://192.168.1.1', { type: 'udp', tag: 'dns_bootstrap', server: '192.168.1.1' }],
			['local', { type: 'local', tag: 'dns_bootstrap' }]
		]) {
			const config = generate([OUT_1], rules, 'out_1', { bootstrap: value });
			assert.deepEqual(config.dns.servers[0], expected, value);
			assert.equal(config.route.default_domain_resolver, 'dns_bootstrap', value);
		}
	});

	test('the chosen resolver does not disturb the tunnel ones', () => {
		const config = generate([OUT_1], [{ domains: ['youtube.com'], target: 'out_1' }], 'direct', {
			bootstrap: 'local'
		});
		assert.deepEqual(dnsTags(config), ['dns_bootstrap', 'dns_out_1']);
		assert.equal(config.dns.final, 'dns_out_1');
		assert.equal(config.dns.servers[1].detour, 'out_1');
	});

	test('a server given by address asks for no resolver', () => {
		for (const outbound of [OUT_ADDR, OUT_ADDR6]) {
			const config = generate([outbound], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct');
			assert.equal('default_domain_resolver' in config.route, false);
			assert.equal('dns' in config, false);
		}
	});

	test('a list fetched directly needs the name of its source', () => {
		const rulesets = [{ tag: 'rs_1', label: '', url: 'https://example.org/a.srs', update_interval: '1d' }];
		const rules = [{ rule_sets: ['rs_1'], target: 'block' }];
		const direct = generate([OUT_ADDR], rules, 'direct', { rulesets });
		assert.equal(direct.route.default_domain_resolver, 'dns_bootstrap');
		assert.deepEqual(dnsTags(direct), ['dns_bootstrap']);

		const detoured = generate([OUT_ADDR], rules, 'direct', { rulesets, rulesetDetour: 'out_1' });
		assert.equal('default_domain_resolver' in detoured.route, false);
		assert.equal('dns' in detoured, false);
	});

	test('lists drive dns only when the whole household asks us', () => {
		const rulesets = [{ tag: 'rs_1', label: '', url: 'https://e.org/a.srs', update_interval: '' }];
		const rules = [{ domains: ['youtube.com'], rule_sets: ['rs_1'], target: 'out_1' }];

		const off = generate([OUT_1], rules, 'direct', { rulesets });
		assert.deepEqual(off.dns.rules.map((r) => r.rule_set), [undefined]);
		assert.equal(off.dns.final, 'dns_out_1');

		const on = generate([OUT_1], rules, 'direct', {
			rulesets, resolveAll: true, bootstrap: 'tls://77.88.8.8'
		});
		assert.ok(on.dns.rules.some((r) => JSON.stringify(r) === JSON.stringify({ rule_set: ['rs_1'], server: 'dns_out_1' })));
		assert.equal(on.dns.final, 'dns_bootstrap');
	});

	test('the listener is always there when the household asks us', () => {
		const listener = { type: 'direct', tag: 'zarap-dns', listen: '127.0.0.1', listen_port: 5353 };
		const rules = [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }];
		assert.equal(
			generate([OUT_1], rules, 'direct').inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)),
			false
		);

		const on = generate([OUT_1], rules, 'direct', { resolveAll: true, bootstrap: 'tls://77.88.8.8' });
		assert.ok(on.inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)));
		assert.deepEqual(on.route.rules[0], { inbound: ['zarap-dns'], action: 'hijack-dns' });
	});

	test('the dns listener appears only with something to resolve', () => {
		const listener = { type: 'direct', tag: 'zarap-dns', listen: '127.0.0.1', listen_port: 5353 };
		const withDomains = generate([OUT_1], [{ domains: ['youtube.com'], target: 'out_1' }], 'direct');
		assert.ok(withDomains.inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)));
		assert.deepEqual(withDomains.route.rules[0], { inbound: ['zarap-dns'], action: 'hijack-dns' });

		for (const target of ['direct', 'block']) {
			const plain = generate([OUT_1], [{ domains: ['youtube.com'], target }], 'direct');
			assert.equal(plain.inbounds.some((i) => JSON.stringify(i) === JSON.stringify(listener)), false);
			assert.deepEqual(dnsTags(plain), ['dns_bootstrap']);
		}
	});

	test('a rule without domains leaves the tunnel resolvers out', () => {
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct');
		assert.deepEqual(dnsTags(config), ['dns_bootstrap']);
		assert.equal('rules' in config.dns, false);
		assert.equal(config.inbounds.length, 1);
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
			'out_1', 'out_42', 'direct', 'block', 'dns', 'main',
			'zarap-tproxy', 'out_', 'proxy', 'Out_1', ''
		];
		const out = runUcode(
			ucode,
			`${prelude}\nfor (let tag in ${JSON.stringify(candidates)}) printf('%s ', valid_outbound_tag(tag));\n`
		);
		assert.deepEqual(out.trim().split(/\s+/), ['true', 'true', ...Array(9).fill('false')]);
	});
});
