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
		'dns_routes', 'dns_domain_tags', 'dnsmasq_take_over', 'dnsmasq_hand_back', 'configure_dnsmasq'
	])}`;

	function runUci(store, rules, enabled, resolveAll) {
		const stub = `
let store = ${JSON.stringify(store)};
function key(config, section, option) { return config + '.' + section + '.' + option; }
let uci = {
	get: function(config, section, option) {
		let value = store[key(config, section, option)];
		return value == null ? null : value;
	},
	set: function(config, section, option, value) { store[key(config, section, option)] = value; },
	delete: function(config, section, option) { delete store[key(config, section, option)]; },
	foreach: function(config, type, fn) { fn({ '.name': 'cfg01' }); }
};
function dnsmasq_section() { return 'cfg01'; }
`;
		return runUcodeJson(
			ucode,
			`${stub}\n${prelude}\nconfigure_dnsmasq(uci, ${JSON.stringify(rules)}, ${enabled ? 'true' : 'false'}, ${resolveAll ? 'true' : 'false'});\nprintf('%J', store);\n`
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
		assert.equal('dhcp.cfg01.noresolv' in result, false);
	});

	test('preserves foreign dnsmasq entries on ports 5354-5399 across enable, takeover, and disable', () => {
		const initial = {
			'dhcp.cfg01.server': ['8.8.8.8', '/corp.test/127.0.0.1#5355', '/lab.test/127.0.0.1#5354']
		};
		// Disabled with empty rules must never touch foreign 127.0.0.1#5355 or #5354
		const idle = runUci({ ...initial }, [], false, false);
		assert.deepEqual(idle['dhcp.cfg01.server'], initial['dhcp.cfg01.server']);
		assert.equal('zarap.main.managed_dns_servers' in idle, false);

		// Scoped apply with two outbounds adds exact Zarap entries and remembers them
		const rules = [
			{ domains: ['youtube.com'], target: 'out_1' },
			{ domains: ['example.com'], target: 'out_2' }
		];
		const scoped = runUci({ ...idle }, rules, true, false);
		assert.deepEqual(scoped['dhcp.cfg01.server'], [
			'8.8.8.8',
			'/corp.test/127.0.0.1#5355',
			'/lab.test/127.0.0.1#5354',
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);
		assert.deepEqual(scoped['zarap.main.managed_dns_servers'], [
			'/youtube.com/127.0.0.1#5353',
			'/example.com/127.0.0.1#5354'
		]);

		// Switching to resolve_all then disabling removes only Zarap's exact entries
		const taken = runUci({ ...scoped }, rules, true, true);
		const disabled = runUci({ ...taken }, rules, false, true);
		assert.deepEqual(disabled['dhcp.cfg01.server'], initial['dhcp.cfg01.server']);
		assert.equal('zarap.main.managed_dns_servers' in disabled, false);
	});

	test('legacy cleanup without managed_dns_servers only removes port 5353', () => {
		const before = {
			'dhcp.cfg01.server': ['8.8.8.8', '/old.example/127.0.0.1#5353', '/corp.test/127.0.0.1#5355']
		};
		const cleaned = runUci({ ...before }, [], false, false);
		assert.deepEqual(cleaned['dhcp.cfg01.server'], ['8.8.8.8', '/corp.test/127.0.0.1#5355']);
	});
});
