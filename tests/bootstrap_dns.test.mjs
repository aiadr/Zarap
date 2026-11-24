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
		'xray_dns_server', 'parse_bootstrap', 'parse_tunnel_dns'
	])}`;

	function parse(value) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', parse_bootstrap(${JSON.stringify(value)}));\n`);
	}

	function parseTunnel(value) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', parse_tunnel_dns(${JSON.stringify(value)}));\n`);
	}

	function toXrayServer(value, localMode, tag = 'dns_bootstrap', domains = [], strict = false) {
		const fn = localMode ? 'parse_bootstrap' : 'parse_tunnel_dns';
		return runUcodeJson(
			ucode,
			`${prelude}\nlet p = ${fn}(${JSON.stringify(value)});\nprintf('%J', xray_dns_server(p, ${localMode ? 'true' : 'false'}, ${JSON.stringify(tag)}, ${JSON.stringify(domains)}, ${strict ? 'true' : 'false'}));\n`
		);
	}

	test('an empty setting falls back to the router itself', () => {
		for (const value of ['', '   ', null]) {
			const parsed = parse(value);
			assert.equal(parsed.ok, true);
			assert.equal(parsed.value, 'local');
			assert.equal(parsed.scheme, 'local');
			assert.deepEqual(toXrayServer(value, true), { address: 'localhost' });
		}
	});

	test('the supported schemes are https, tcp and udp', () => {
		for (const [input, expectedValue, expectedScheme, expectedAddr] of [
			['https://1.1.1.1', 'https://1.1.1.1/dns-query', 'https', 'https+local://1.1.1.1/dns-query'],
			['https://1.1.1.1/custom', 'https://1.1.1.1/custom', 'https', 'https+local://1.1.1.1/custom'],
			['udp://8.8.8.8', 'udp://8.8.8.8', 'udp', '8.8.8.8'],
			['tcp://8.8.4.4', 'tcp://8.8.4.4', 'tcp', 'tcp+local://8.8.4.4']
		]) {
			const parsed = parse(input);
			assert.equal(parsed.ok, true, input);
			assert.equal(parsed.scheme, expectedScheme);
			assert.equal(parsed.value, expectedValue);
			const srv = toXrayServer(input, true);
			assert.equal(srv.address, expectedAddr);
			if (expectedScheme === 'udp')
				assert.equal(srv.tag, 'dns_bootstrap');
			else
				assert.equal('tag' in srv, false);
		}
	});

	test('dot (tls://) and #sni fragments are rejected with clear guidance', () => {
		const dot = parse('tls://9.9.9.9');
		assert.equal(dot.kind, 'input_error');
		assert.ok(dot.error.includes('tls://'));

		const frag = parse('https://77.88.8.8/dns-query#common.dns.yandex.net');
		assert.equal(frag.kind, 'input_error');
		assert.ok(frag.error.includes('#'));
	});

	test('a bare address is a plain udp query', () => {
		const parsed = parse('192.168.1.1');
		assert.equal(parsed.ok, true);
		assert.equal(parsed.scheme, 'udp');
		assert.equal(parsed.host, '192.168.1.1');
		assert.equal(parsed.value, 'udp://192.168.1.1');
		assert.deepEqual(toXrayServer('192.168.1.1', true), { address: '192.168.1.1', tag: 'dns_bootstrap' });
	});

	test('the router can be asked to resolve it itself', () => {
		for (const value of ['local', 'LOCAL']) {
			const parsed = parse(value);
			assert.equal(parsed.ok, true, value);
			assert.equal(parsed.value, 'local');
			assert.deepEqual(toXrayServer(value, true), { address: 'localhost' });
		}
	});

	test('a port is carried and bounded', () => {
		const parsed = parse('udp://192.168.1.1:5353');
		assert.equal(parsed.ok, true);
		assert.equal(parsed.port, 5353);
		assert.equal(parsed.value, 'udp://192.168.1.1:5353');
		assert.deepEqual(toXrayServer('udp://192.168.1.1:5353', true), {
			address: '192.168.1.1', port: 5353, tag: 'dns_bootstrap'
		});
		for (const value of ['udp://8.8.8.8:0', 'udp://8.8.8.8:65536', 'udp://8.8.8.8:dns'])
			assert.equal(parse(value).kind, 'input_error', value);
	});

	test('a doh path defaults to /dns-query and is refused elsewhere', () => {
		assert.equal(parse('https://1.1.1.1').path, '/dns-query');
		assert.equal(parse('https://1.1.1.1/').path, '/dns-query');
		assert.equal(parse('https://1.1.1.1/dns-query').path, '/dns-query');
		assert.equal(parse('https://1.1.1.1:8443/doh').value, 'https://1.1.1.1:8443/doh');
		assert.equal(parse('udp://8.8.8.8/dns-query').kind, 'input_error');
		assert.equal(parse('tcp://8.8.8.8/dns-query').kind, 'input_error');
	});

	test('a domain name is refused because it would loop', () => {
		const parsed = parse('https://cloudflare-dns.com/dns-query');
		assert.equal(parsed.kind, 'input_error');
		assert.ok(parsed.error.includes('имя'));
	});

	test('ipv6 and unknown schemes are named in the refusal', () => {
		assert.equal(parse('udp://[2606:4700:4700::1111]').kind, 'input_error');
		const unknown = parse('quic://1.1.1.1');
		assert.equal(unknown.kind, 'input_error');
		assert.ok(unknown.error.includes('quic'));
	});

	test('the tunnel resolver uses routed schemes and rejects local', () => {
		assert.equal(parseTunnel('').value, 'https://1.1.1.1/dns-query');
		assert.deepEqual(toXrayServer('', false, 'dns_out_1', ['domain:youtube.com'], true), {
			address: 'https://1.1.1.1/dns-query',
			tag: 'dns_out_1',
			domains: ['domain:youtube.com'],
			skipFallback: true,
			finalQuery: true
		});
		assert.deepEqual(toXrayServer('tcp://9.9.9.9', false, 'dns_out_1', [], false), {
			address: 'tcp://9.9.9.9',
			tag: 'dns_out_1'
		});
		assert.deepEqual(toXrayServer('udp://1.1.1.1:53', false, 'dns_out_1', [], false), {
			address: '1.1.1.1',
			port: 53,
			tag: 'dns_out_1'
		});
		const refused = parseTunnel('local');
		assert.equal(refused.kind, 'input_error');
		assert.ok(refused.error.includes('local'));
	});
});
