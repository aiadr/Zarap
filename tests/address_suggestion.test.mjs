import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftMany, readBackend, runUcode } from './ucode_helper.mjs';

const ucode = findUcode();

describe('address_suggester', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const prelude = liftMany(readBackend(), [
		'valid_ipv4', 'ipv4_number', 'ipv4_text', 'address_suggester'
	]);

	function suggest(count, router, mask, { staticLeases = [], dynamicLeases = [] } = {}) {
		const byIp = Object.fromEntries(staticLeases.map((ip) => [ip, { ip }]));
		const dynamic = Object.fromEntries(
			dynamicLeases.map((ip, n) => [`00:00:00:00:00:${n.toString(16).padStart(2, '0')}`, { ip }])
		);
		const stubs = `
function lan_ipv4() { return ${router ? JSON.stringify({ address: router, mask }) : 'null'}; }
function static_leases() { return { by_ip: ${JSON.stringify(byIp)}, by_mac: {} }; }
function current_dhcp_leases() { return ${JSON.stringify(dynamic)}; }
`;
		const script = `${stubs}\n${prelude}\nlet next = address_suggester();\nfor (let i = 0; i < ${count}; i++)\n\tprint(next(), '\\n');\n`;
		return runUcode(ucode, script).replace(/\n$/, '').split('\n');
	}

	test('skips the router and every lease', () => {
		assert.deepEqual(
			suggest(2, '192.168.10.1', 24, {
				staticLeases: ['192.168.10.2'],
				dynamicLeases: ['192.168.10.3']
			}),
			['192.168.10.4', '192.168.10.5']
		);
	});

	test('hands out a different address each time', () => {
		const addresses = suggest(3, '192.168.1.1', 24);
		assert.deepEqual(addresses, ['192.168.1.2', '192.168.1.3', '192.168.1.4']);
		assert.equal(new Set(addresses).size, 3);
	});

	test('stays inside the lan prefix', () => {
		assert.deepEqual(suggest(1, '10.9.8.7', 16), ['10.9.0.1']);
	});

	test('offers nothing when ubus cannot name the lan', () => {
		assert.deepEqual(suggest(1, null, 24), ['']);
	});

	test('offers nothing once the subnet is full', () => {
		const taken = Array.from({ length: 254 }, (_, i) => `192.168.1.${i + 1}`);
		assert.deepEqual(suggest(1, '192.168.1.1', 24, { staticLeases: taken }), ['']);
	});
});
