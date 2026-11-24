import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftConstants, liftMany, readBackend, runUcodeJson } from './ucode_helper.mjs';

const ucode = findUcode();

describe('bootstrap_dns', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const constants = liftConstants(source, [
		'const DNS_UPSTREAM', 'const BOOTSTRAP_TAG',
		'const BOOTSTRAP_DEFAULT', 'const BOOTSTRAP_SCHEMES',
		'const TUNNEL_DEFAULT'
	]);
	const prelude = `${constants}\n${liftMany(source, [
		'result_error', 'input_error', 'valid_ipv4', 'parse_resolver',
		'parse_bootstrap', 'parse_tunnel_dns'
	])}`;

	function parse(value) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', parse_bootstrap(${JSON.stringify(value)}));\n`);
	}

	function parseTunnel(value) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', parse_tunnel_dns(${JSON.stringify(value)}));\n`);
	}

	test('an empty setting falls back to the router itself', () => {
		for (const value of ['', '   ', null]) {
			const parsed = parse(value);
			assert.equal(parsed.ok, true);
			assert.equal(parsed.value, 'local');
			assert.deepEqual(parsed.server, { type: 'local', tag: 'dns_bootstrap' });
		}
	});

	test('the scheme decides what leaves the router', () => {
		for (const [value, expected] of [
			['https://1.1.1.1', 'https'],
			['tls://9.9.9.9', 'tls'],
			['udp://8.8.8.8', 'udp'],
			['tcp://8.8.4.4', 'tcp']
		]) {
			const parsed = parse(value);
			assert.equal(parsed.ok, true, value);
			assert.equal(parsed.server.type, expected);
			assert.equal(parsed.value, value);
			assert.equal('detour' in parsed.server, false);
		}
	});

	test('a bare address is a plain query', () => {
		const parsed = parse('192.168.1.1');
		assert.equal(parsed.ok, true);
		assert.deepEqual(parsed.server, { type: 'udp', tag: 'dns_bootstrap', server: '192.168.1.1' });
		assert.equal(parsed.value, 'udp://192.168.1.1');
	});

	test('the router can be asked to resolve it itself', () => {
		for (const value of ['local', 'LOCAL']) {
			const parsed = parse(value);
			assert.equal(parsed.ok, true, value);
			assert.equal(parsed.value, 'local');
			assert.deepEqual(parsed.server, { type: 'local', tag: 'dns_bootstrap' });
		}
	});

	test('a port is carried and bounded', () => {
		const parsed = parse('udp://192.168.1.1:5353');
		assert.equal(parsed.ok, true);
		assert.equal(parsed.server.server_port, 5353);
		assert.equal(parsed.value, 'udp://192.168.1.1:5353');
		for (const value of ['udp://8.8.8.8:0', 'udp://8.8.8.8:65536', 'udp://8.8.8.8:dns'])
			assert.equal(parse(value).kind, 'input_error', value);
	});

	test('a doh path is kept and refused elsewhere', () => {
		const parsed = parse('https://1.1.1.1/dns-query');
		assert.equal(parsed.ok, true);
		assert.equal(parsed.server.path, '/dns-query');
		assert.equal('path' in parse('https://1.1.1.1/').server, false);
		assert.equal(parse('udp://8.8.8.8/dns-query').kind, 'input_error');
	});

	test('a name is refused because it would need this very resolver', () => {
		const parsed = parse('https://cloudflare-dns.com');
		assert.equal(parsed.kind, 'input_error');
		assert.ok(parsed.error.includes('имя'));
		assert.ok(parsed.error.includes('адрес#имя'));
	});

	test('an encrypted resolver can be dialled by address and checked by name', () => {
		const parsed = parse('tls://77.88.8.8#common.dot.dns.yandex.net');
		assert.equal(parsed.ok, true, parsed.error);
		assert.deepEqual(parsed.server, {
			type: 'tls', tag: 'dns_bootstrap', server: '77.88.8.8',
			tls: { enabled: true, server_name: 'common.dot.dns.yandex.net' }
		});
		assert.equal(parsed.value, 'tls://77.88.8.8#common.dot.dns.yandex.net');

		const doh = parse('https://77.88.8.8:8443/dns-query#common.dns.yandex.net');
		assert.equal(doh.ok, true, doh.error);
		assert.equal(doh.server.server_port, 8443);
		assert.equal(doh.server.path, '/dns-query');
		assert.equal(doh.server.tls.server_name, 'common.dns.yandex.net');
	});

	test('a certificate name makes no sense without encryption', () => {
		for (const value of ['udp://77.88.8.8#dns.yandex.net', 'tcp://77.88.8.8#dns.yandex.net'])
			assert.equal(parse(value).kind, 'input_error', value);
		assert.equal(parse('tls://77.88.8.8#не имя').kind, 'input_error');
	});

	test('ipv6 and unknown schemes are named in the refusal', () => {
		assert.equal(parse('udp://[2606:4700:4700::1111]').kind, 'input_error');
		const unknown = parse('quic://1.1.1.1');
		assert.equal(unknown.kind, 'input_error');
		assert.ok(unknown.error.includes('quic'));
	});

	test('the tunnel resolver is its own setting', () => {
		assert.equal(parseTunnel('').value, 'https://1.1.1.1');
		assert.deepEqual(parseTunnel('').server, { type: 'https', server: '1.1.1.1' });
		assert.equal(parseTunnel('tls://9.9.9.9').server.type, 'tls');
		const refused = parseTunnel('local');
		assert.equal(refused.kind, 'input_error');
		assert.ok(refused.error.includes('local'));
	});
});
