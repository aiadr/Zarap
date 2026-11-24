import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftConstants, liftMany, readBackend, runUcodeJson } from './ucode_helper.mjs';

const ucode = findUcode();

describe('dnsmasq_takeover', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const constants = liftConstants(source, [
		'const DNS_PORT', 'const DNS_FORWARD', 'const DNS_TAKEOVER'
	]);
	const prelude = `${constants}\n${liftMany(source, [
		'dns_routes', 'dns_domain_tags', 'dnsmasq_take_over', 'dnsmasq_hand_back',
		'dns_forward_entries', 'uci_dns_rules', 'configure_dnsmasq'
	])}`;

	function runUci(store, rules, enabled, resolveAll, { savedRules = null, previousRules = undefined } = {}) {
		const prevArg = previousRules === undefined ? '' : `, ${JSON.stringify(previousRules)}`;
		const stub = `
let store = ${JSON.stringify(store)};
let saved_rules = ${JSON.stringify(savedRules || [])};
function key(config, section, option) { return config + '.' + section + '.' + option; }
let uci = {
	get: function(config, section, option) {
		let value = store[key(config, section, option)];
		return value == null ? null : value;
	},
	set: function(config, section, option, value) { store[key(config, section, option)] = value; },
	delete: function(config, section, option) { delete store[key(config, section, option)]; },
	foreach: function(config, type, fn) {
		if (config == 'zarap' && type == 'rule') {
			for (let i = 0; i < length(saved_rules); i++)
				fn(saved_rules[i]);
			return;
		}
		fn({ '.name': 'cfg01' });
	}
};
function dnsmasq_section() { return 'cfg01'; }
`;
		return runUcodeJson(
			ucode,
			`${stub}\n${prelude}\nconfigure_dnsmasq(uci, ${JSON.stringify(rules)}, ${enabled ? 'true' : 'false'}, ${resolveAll ? 'true' : 'false'}${prevArg});\nprintf('%J', store);\n`
		);
	}

	test('remembers what it took and gives it back', () => {
		const before = {
			'dhcp.cfg01.server': ['77.88.8.8', '77.88.8.1'],
			'dhcp.cfg01.cachesize': '1000'
		};
		const taken = runUci({ ...before }, [], true, true);
		assert.deepEqual(taken['dhcp.cfg01.server'], ['127.0.0.1#5353']);
		assert.equal(taken['dhcp.cfg01.noresolv'], '1');
		assert.equal(taken['dhcp.cfg01.cachesize'], '0');
		assert.deepEqual(taken['zarap.main.saved_dns_server'], ['77.88.8.8', '77.88.8.1']);
		assert.equal(taken['zarap.main.saved_dns_cachesize'], '1000');
		assert.equal(taken['zarap.main.saved_dns_noresolv'], '');

		const back = runUci({ ...taken }, [], false, true);
		assert.deepEqual(back['dhcp.cfg01.server'], before['dhcp.cfg01.server']);
		assert.equal(back['dhcp.cfg01.cachesize'], before['dhcp.cfg01.cachesize']);
		assert.equal('dhcp.cfg01.noresolv' in back, false);
		for (const key of ['server', 'noresolv', 'cachesize'])
			assert.equal(`zarap.main.saved_dns_${key}` in back, false);
	});

	test('applying twice does not remember our own values', () => {
		const once = runUci({ 'dhcp.cfg01.server': ['8.8.8.8'] }, [], true, true);
		const twice = runUci({ ...once }, [], true, true);
		assert.deepEqual(twice['zarap.main.saved_dns_server'], ['8.8.8.8']);
	});

	test('switching zarap off hands dns back and clears domain forwarding', () => {
		const rules = [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['example.com'], target: 'out_2' }
		];
		const taken = runUci({ 'dhcp.cfg01.server': ['8.8.8.8'] }, rules, true, true);
		assert.deepEqual(taken['dhcp.cfg01.server'], [
			'127.0.0.1#5353',
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		const off = runUci({ ...taken }, rules, false, true);
		assert.deepEqual(off['dhcp.cfg01.server'], ['8.8.8.8']);

		const scoped = runUci({ 'dhcp.cfg01.server': ['8.8.8.8'] }, rules, true, false);
		assert.deepEqual(scoped['dhcp.cfg01.server'], [
			'8.8.8.8',
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		const scopedOff = runUci({ ...scoped }, rules, false, false);
		assert.deepEqual(scopedOff['dhcp.cfg01.server'], ['8.8.8.8']);
	});

	test('without the mode only the named domains are forwarded per outbound port', () => {
		const rules = [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['.example.com'], target: 'out_2' }
		];
		const result = runUci({ 'dhcp.cfg01.server': ['8.8.8.8'] }, rules, true, false);
		assert.deepEqual(result['dhcp.cfg01.server'], [
			'8.8.8.8',
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		assert.deepEqual(result['zarap.main.managed_dns_servers'], [
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		assert.equal(result['zarap.main.managed_dns_tracked'], '1');
		assert.equal('dhcp.cfg01.noresolv' in result, false);
	});

	test('preserves foreign dnsmasq entries even on ports 5353-5399 across enable, takeover, and disable', () => {
		const initial = {
			'dhcp.cfg01.server': [
				'8.8.8.8',
				'/corp.test/127.0.0.1#5353',
				'/lab.test/127.0.0.1#5354',
				'/other.test/127.0.0.1#5355'
			]
		};
		// Disabled with empty rules must never touch foreign 127.0.0.1#5353..5355
		// and must keep managed_dns_tracked='1' even with an empty managed list.
		const idle = runUci({ ...initial }, [], false, false);
		assert.deepEqual(idle['dhcp.cfg01.server'], initial['dhcp.cfg01.server']);
		assert.equal(idle['zarap.main.managed_dns_tracked'], '1');
		assert.equal('zarap.main.managed_dns_servers' in idle, false);

		// A second empty apply stays tracked and never falls back to legacy cleanup.
		const idleAgain = runUci({ ...idle }, [], false, false);
		assert.deepEqual(idleAgain['dhcp.cfg01.server'], initial['dhcp.cfg01.server']);
		assert.equal(idleAgain['zarap.main.managed_dns_tracked'], '1');

		// Scoped apply with two outbounds adds exact Zarap entries and remembers them.
		const rules = [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['example.com'], target: 'out_2' }
		];
		const scoped = runUci({ ...idleAgain }, rules, true, false);
		assert.deepEqual(scoped['dhcp.cfg01.server'], [
			...initial['dhcp.cfg01.server'],
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		assert.deepEqual(scoped['zarap.main.managed_dns_servers'], [
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);

		// Switching to resolve_all then disabling removes only Zarap's exact entries.
		const taken = runUci({ ...scoped }, rules, true, true);
		const disabled = runUci({ ...taken }, rules, false, true);
		assert.deepEqual(disabled['dhcp.cfg01.server'], initial['dhcp.cfg01.server']);
		assert.equal(disabled['zarap.main.managed_dns_tracked'], '1');
		assert.equal('zarap.main.managed_dns_servers' in disabled, false);
	});

	test('migrates multi-port 04a52c9 entries on disable without deleting foreign port 5353 entries', () => {
		const before = {
			'dhcp.cfg01.server': [
				'8.8.8.8',
				'/corp.test/127.0.0.1#5353',
				'/one.test/127.0.0.1#5353',
				'/two.test/127.0.0.1#5354'
			]
		};
		const rules = [
			{ domains: ['one.test'], target: 'out_1' },
			{ domains: ['two.test'], target: 'out_2' }
		];
		// Direct call (as in unit harness without UCI rule sections): both 5353 and 5354 are removed.
		const disabledDirect = runUci({ ...before }, rules, false, false);
		assert.deepEqual(disabledDirect['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5353']);
		assert.equal(disabledDirect['zarap.main.managed_dns_tracked'], '1');

		// Router upgrade where user also deletes all rules in the same apply:
		// saved UCI rules still clean both old entries while keeping /corp.test/127.0.0.1#5353.
		const savedRules = [
			{ domain: ['one.test'], target: 'out_1' },
			{ domain: ['two.test'], target: 'out_2' }
		];
		const wiped = runUci({ ...before }, [], false, false, { savedRules });
		assert.deepEqual(wiped['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5353']);
		assert.equal(wiped['zarap.main.managed_dns_tracked'], '1');

		// Upgrade from 04a52c9 directly into resolve_all=true, then disable:
		// old 5353 + 5354 entries are migrated before takeover and cleaned on hand-back.
		const taken = runUci({ ...before }, rules, true, true, { savedRules });
		assert.equal(taken['zarap.main.managed_dns_tracked'], '1');
		const backOff = runUci({ ...taken }, rules, false, true);
		assert.deepEqual(backOff['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5353']);
	});

	test('migrates single-port main entries from saved rules while preserving foreign port 5353', () => {
		const before = {
			'dhcp.cfg01.server': [
				'8.8.8.8',
				'/corp.test/127.0.0.1#5353',
				'/one.test/127.0.0.1#5353',
				'/two.test/127.0.0.1#5353'
			]
		};
		const savedRules = [
			{ domain: ['one.test'], target: 'out_1' },
			{ domain: ['.two.test'], target: 'out_2' }
		];
		const cleaned = runUci({ ...before }, [], false, false, { savedRules });
		assert.deepEqual(cleaned['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5353']);
		assert.equal(cleaned['zarap.main.managed_dns_tracked'], '1');
	});

	test('migrates multi-port entries when a rule_set-only rule precedes manual domains', () => {
		// Exact reviewer regression: rule 0 has geosite on out_2, rule 1 has
		// one.test on out_1, rule 2 has two.test on out_2 -> out_2 owns 5353,
		// out_1 owns 5354 (and rule_set-only out_3 consumes no port).
		const before = {
			'dhcp.cfg01.server': [
				'8.8.8.8',
				'/corp.test/127.0.0.1#5353',
				'/two.test/127.0.0.1#5353',
				'/one.test/127.0.0.1#5354'
			]
		};
		const savedRules = [
			{ rule_set: ['rs_0'], target: 'out_3' },
			{ rule_set: ['rs_1'], target: 'out_2' },
			{ domain: ['one.test'], target: 'out_1' },
			{ domain: ['two.test'], target: 'out_2' }
		];
		const cleaned = runUci({ ...before }, [], false, false, { savedRules });
		assert.deepEqual(cleaned['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5353']);
		assert.equal(cleaned['zarap.main.managed_dns_tracked'], '1');
	});

	test('treats existing managed_dns_servers as complete without guessing legacy entries for the same domain', () => {
		const before = {
			'dhcp.cfg01.server': [
				'8.8.8.8',
				'/one.test/127.0.0.1#5353',
				'/one.test/127.0.0.1#5354'
			],
			'zarap.main.managed_dns_servers': ['/one.test/127.0.0.1#5354']
		};
		const savedRules = [{ domain: ['one.test'], target: 'out_1' }];
		const cleaned = runUci({ ...before }, [{ domains: ['one.test'], target: 'out_1' }], false, false, { savedRules });
		assert.deepEqual(cleaned['dhcp.cfg01.server'], ['8.8.8.8', '/one.test/127.0.0.1#5353']);
		assert.equal(cleaned['zarap.main.managed_dns_tracked'], '1');
		assert.equal('zarap.main.managed_dns_servers' in cleaned, false);
	});
});
