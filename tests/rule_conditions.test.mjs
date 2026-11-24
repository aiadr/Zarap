import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftConstants, liftMany, readBackend, runUcode, runUcodeJson } from './ucode_helper.mjs';

const TV = '00:11:22:33:44:55';
const TABLET = '10:20:30:40:50:60';

const ucode = findUcode();

describe('rule_conditions', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const constants = liftConstants(source, ['const RULESET_INTERVAL_DEFAULT']);
	const prelude = `${constants}\n${liftMany(source, [
		'result_error', 'input_error', 'normalize_mac', 'is_private_mac',
		'valid_ipv4', 'normalize_domain', 'normalize_cidr', 'normalize_port',
		'valid_target', 'valid_ruleset_tag', 'validate_rulesets',
		'validate_ruleset_detour', 'validate_ruleset_interval', 'validate_rule_list',
		'validate_rules', 'startup_hint'
	])}`;

	function evalJson(expr) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', ${expr});\n`);
	}

	function validate(rules, tags = { out_1: true }, declared = {}) {
		return evalJson(`validate_rules(${JSON.stringify(rules)}, ${JSON.stringify(tags)}, ${JSON.stringify(declared)})`);
	}

	function refusal(rules) {
		const result = validate(rules);
		assert.equal(result.ok, false, JSON.stringify(result));
		assert.equal(result.kind, 'input_error');
		return result.error;
	}

	function accepted(rule) {
		const result = validate([rule]);
		assert.equal(result.ok, true, JSON.stringify(result));
		return result.rules[0];
	}

	function rulesets(entries) {
		return evalJson(`validate_rulesets(${JSON.stringify(entries)})`);
	}

	function detour(value, tags = { out_1: true }) {
		return evalJson(`validate_ruleset_detour(${JSON.stringify(value)}, ${JSON.stringify(tags)})`);
	}

	function interval(value) {
		return evalJson(`validate_ruleset_interval(${JSON.stringify(value)})`);
	}

	function hint(entries) {
		return runUcode(ucode, `${prelude}\nprintf('%s', startup_hint(${JSON.stringify(entries)}));\n`);
	}

	test('a rule needs at least one condition', () => {
		assert.ok(refusal([{ target: 'out_1' }]).includes('хотя бы одно условие'));
	});

	test('any single condition is enough', () => {
		for (const rule of [
			{ clients: [TV] },
			{ domains: ['example.com'] },
			{ ip_cidr: ['10.0.0.0/8'] },
			{ ports: ['443'] },
			{ network: 'udp' }
		]) {
			assert.equal(validate([{ ...rule, target: 'out_1' }]).ok, true, JSON.stringify(rule));
		}
	});

	test('a domain is kept as written and lowercased', () => {
		const rule = accepted({ domains: ['YouTube.com', '.googlevideo.com'], target: 'out_1' });
		assert.deepEqual(rule.domains, ['youtube.com', '.googlevideo.com']);
	});

	test('a domain with a scheme or a path is refused', () => {
		assert.ok(refusal([{ domains: ['https://youtube.com'], target: 'out_1' }]).includes('без схемы'));
		assert.ok(refusal([{ domains: ['youtube.com/watch'], target: 'out_1' }]).includes('без схемы'));
	});

	test('a star is refused with what to write instead', () => {
		const message = refusal([{ domains: ['*.example.com'], target: 'out_1' }]);
		assert.ok(message.includes('Звёздочка'));
		assert.ok(message.includes('точки'));
	});

	test('a cyrillic domain is refused asking for punycode', () => {
		assert.ok(refusal([{ domains: ['сайт.рф'], target: 'out_1' }]).includes('punycode'));
	});

	test('something that is not a domain is refused', () => {
		for (const value of ['youtube', '', '.', 'youtube..com', 'you tube.com'])
			refusal([{ domains: [value], target: 'out_1' }]);
	});

	test('a bare address becomes its own range', () => {
		assert.deepEqual(
			accepted({ ip_cidr: ['93.184.216.34'], target: 'out_1' }).ip_cidr,
			['93.184.216.34/32']
		);
	});

	test('a mask is kept and bounded', () => {
		assert.deepEqual(
			accepted({ ip_cidr: ['10.0.0.0/8'], target: 'out_1' }).ip_cidr,
			['10.0.0.0/8']
		);
		assert.ok(refusal([{ ip_cidr: ['10.0.0.0/33'], target: 'out_1' }]).includes('маска'));
	});

	test('ipv6 is refused by name', () => {
		assert.ok(refusal([{ ip_cidr: ['2001:db8::/32'], target: 'out_1' }]).includes('IPv6'));
	});

	test('a range that is not a range is refused', () => {
		for (const value of ['10.0.0.256/8', '10.0.0.0/8/8', '', 'example.com'])
			refusal([{ ip_cidr: [value], target: 'out_1' }]);
	});

	test('ports keep their form', () => {
		const rule = accepted({ ports: ['443', '1000:2000'], target: 'out_1' });
		assert.deepEqual(rule.ports, ['443', '1000:2000']);
	});

	test('ports are bounded and ordered', () => {
		for (const value of ['0', '65536', '-1', '443x', ''])
			refusal([{ ports: [value], target: 'out_1' }]);
		assert.ok(refusal([{ ports: ['2000:1000'], target: 'out_1' }]).includes('начало больше конца'));
	});

	test('only tcp and udp are protocols', () => {
		assert.equal(accepted({ network: 'UDP', target: 'out_1' }).network, 'udp');
		assert.ok(refusal([{ network: 'icmp', target: 'out_1' }]).includes('tcp или udp'));
	});

	test('a repeat inside one rule is refused', () => {
		assert.ok(refusal([{ ip_cidr: ['10.0.0.0/8', '10.0.0.0/8'], target: 'out_1' }]).includes('дважды'));
		assert.ok(refusal([{ ports: ['443', '443'], target: 'out_1' }]).includes('дважды'));
	});

	test('the same range in two rules is allowed', () => {
		assert.equal(validate([
			{ ip_cidr: ['10.0.0.0/8'], target: 'out_1' },
			{ ip_cidr: ['10.0.0.0/8'], target: 'block' }
		]).ok, true);
	});

	test('conditions do not loosen the checks on devices', () => {
		assert.ok(refusal([
			{ clients: ['02:11:22:33:44:55'], ip_cidr: ['10.0.0.0/8'], target: 'out_1' }
		]).includes('приватный MAC'));
	});

	test('a missing list is an empty one', () => {
		const rule = accepted({ clients: [TV], target: 'out_1' });
		assert.deepEqual(rule.domains, []);
		assert.deepEqual(rule.ip_cidr, []);
		assert.deepEqual(rule.ports, []);
		assert.equal(rule.network, '');
	});

	test('a list of the wrong type is refused', () => {
		assert.ok(refusal([{ ip_cidr: '10.0.0.0/8', target: 'out_1' }]).includes('неверный формат'));
	});

	test('the target is still checked', () => {
		assert.ok(refusal([{ ip_cidr: ['10.0.0.0/8'], target: 'out_9' }]).includes('несуществующее подключение'));
		for (const target of ['direct', 'block', 'out_1'])
			assert.equal(validate([{ clients: [TABLET], target }]).ok, true);
	});

	test('a ruleset needs a name, https address, kind and category', () => {
		const good = rulesets([{
			tag: 'rs_1', label: 'YouTube',
			url: 'https://example.org/geosite.dat',
			kind: 'geosite', category: 'youtube'
		}, {
			tag: 'rs_2', label: 'Telegram IP',
			url: 'https://example.org/geoip.dat',
			kind: 'geoip', category: 'telegram'
		}]);
		assert.equal(good.ok, true, JSON.stringify(good));
		assert.equal('detour' in good.rulesets[0], false);
		assert.equal('update_interval' in good.rulesets[0], false);
		assert.equal(good.rulesets[0].kind, 'geosite');
		assert.equal(good.rulesets[0].category, 'youtube');
		assert.equal(good.rulesets[1].kind, 'geoip');
		assert.equal(good.rulesets[1].category, 'telegram');

		assert.ok(rulesets([{ tag: 'ads', url: 'https://example.org/a.dat', category: 'ads' }]).error.includes('Некорректное имя'));
		assert.ok(rulesets([{ tag: 'rs_1', url: 'http://example.org/a.dat', category: 'ads' }]).error.includes('https://'));
		assert.ok(rulesets([{ tag: 'rs_1', url: 'example.org/a.dat', category: 'ads' }]).error.includes('https://'));
		assert.ok(rulesets([{ tag: 'rs_1', url: 'https://example.org/a.dat', kind: 'domain', category: 'ads' }]).error.includes('geosite'));
		assert.ok(rulesets([{ tag: 'rs_1', url: 'https://example.org/a.dat', kind: 'geosite', category: '' }]).error.includes('категорию'));
		assert.ok(rulesets([{ tag: 'rs_1', url: 'https://example.org/a.dat', kind: 'geosite', category: 'bad cat!' }]).error.includes('категорию'));
	});

	test('one schedule answers for every list', () => {
		assert.equal(interval('12h').interval, '12h');
		assert.equal(interval('1d').interval, '1d');
		assert.equal(interval('168h').interval, '168h');
		assert.equal(interval('').interval, '');
		assert.equal(interval('off').interval, '');
		assert.equal(interval(null).interval, '1d');
		assert.ok(interval('каждый день').error.includes('12h'));
	});

	test('one detour answers for every list', () => {
		assert.equal(detour('out_1').detour, 'out_1');
		assert.equal(detour('direct').detour, 'direct');
		assert.equal(detour('').detour, 'direct');
		assert.equal(detour(null).detour, 'direct');
		assert.ok(detour('out_9').error.includes('несуществующее подключение'));
	});

	test('a rule points only at a declared set', () => {
		assert.ok(validate([{ rule_sets: ['rs_1'], target: 'out_1' }]).error.includes('несуществующий набор'));
		assert.equal(validate([{ rule_sets: ['rs_1'], target: 'out_1' }], { out_1: true }, { rs_1: true }).ok, true);
	});

	test('a failed start names the rule sets as a suspect', () => {
		const message = hint([{ tag: 'rs_1', label: 'Реклама' }]);
		assert.ok(message.includes('Реклама (rs_1)'));
		assert.ok(message.includes('журнале'));
	});

	test('without rule sets the failure says nothing about them', () => {
		assert.equal(hint([]), '');
	});

	test('the order of the rules is kept', () => {
		const result = validate([
			{ clients: [TV], target: 'out_1' },
			{ ports: ['443'], target: 'block' }
		]);
		assert.deepEqual(result.rules.map((r) => r.target), ['out_1', 'block']);
	});
});
