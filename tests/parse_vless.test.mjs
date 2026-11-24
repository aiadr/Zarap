import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftMany, readBackend, runUcodeJson } from './ucode_helper.mjs';

const UUID = '123e4567-e89b-42d3-a456-426614174000';
const PBK = '0123456789abcdefghijklmnopqrstuvwxyzABCDE';
const BASE_PARAMS = `security=reality&sni=cdn.example.test&fp=chrome&pbk=${PBK}&type=tcp`;

// luci.http is unavailable outside rpcd.
const STUBS = `
function urldecode(s) {
	s = replace(s || '', /\\+/g, ' ');
	return replace(s, /%([0-9A-Fa-f]{2})/g, function(m, h) { return chr(hex(h)); });
}
function urldecode_params(q) {
	let out = {};
	for (let pair in split(q || '', '&')) {
		if (!pair) continue;
		let eq = index(pair, '=');
		out[urldecode(eq >= 0 ? substr(pair, 0, eq) : pair)] =
			urldecode(eq >= 0 ? substr(pair, eq + 1) : '');
	}
	return out;
}
`;

const ucode = findUcode();

describe('parse_vless', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const prelude = STUBS + liftMany(readBackend(), ['result_error', 'input_error', 'parse_vless']);

	function parse(link) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', parse_vless(${JSON.stringify(link)}));\n`);
	}

	test('accepts an empty path before the query', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443/?${BASE_PARAMS}`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.server_port, 443);
		assert.equal(result.config.server, 'proxy.example.test');
	});

	test('accepts the canonical form', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.server_port, 443);
	});

	test('accepts a path together with a fragment', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:8443/?${BASE_PARAMS}#My%20Server`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.server_port, 8443);
	});

	test('accepts a bracketed ipv6 server', () => {
		const result = parse(`vless://${UUID}@[2001:db8::1]:443?${BASE_PARAMS}`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.server, '2001:db8::1');
	});

	test('accepts the vision flow', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}&flow=xtls-rprx-vision`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.flow, 'xtls-rprx-vision');
	});

	test('survives invisible characters from a paste', () => {
		for (const [label, intruder] of [
			['space', ' '],
			['non-breaking space', '\u00a0'],
			['zero-width space', '\u200b'],
			['tab', '\t']
		]) {
			const link = `vless://${UUID}@proxy.example.test:443${intruder}?${BASE_PARAMS}`;
			const result = parse(link);
			assert.equal(result.ok, true, `${label}: ${result.error}`);
			assert.equal(result.config.server_port, 443);
		}
	});

	test('survives a leading byte order mark', () => {
		const result = parse(`\ufeffvless://${UUID}@proxy.example.test:443?${BASE_PARAMS}`);
		assert.equal(result.ok, true, result.error);
	});

	test('keeps the connection name from the fragment', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}#My%20Server`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.name, 'My Server');
	});

	test('keeps a name written in another script', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}#Мой сервер`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.name, 'Мой сервер');
	});

	test('a link without a fragment has no name', () => {
		const result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}`);
		assert.equal(result.ok, true, result.error);
		assert.equal(result.config.name, '');
	});

	test('a name is stripped of control characters and bounded', () => {
		let result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}#one\ntwo`);
		assert.equal(result.config.name, 'onetwo');
		result = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}#${'x'.repeat(200)}`);
		assert.equal(result.config.name.length, 64);
	});

	test('rejects a port outside the valid range', () => {
		for (const port of ['0', '70000']) {
			const result = parse(`vless://${UUID}@proxy.example.test:${port}?${BASE_PARAMS}`);
			assert.equal(result.ok, false);
			assert.equal(result.kind, 'input_error');
		}
	});

	test('rejects transports and securities outside the mvp', () => {
		const ws = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}`.replace('type=tcp', 'type=ws'));
		assert.equal(ws.ok, false);
		const plain = parse(`vless://${UUID}@proxy.example.test:443?${BASE_PARAMS}`.replace('security=reality', 'security=tls'));
		assert.equal(plain.ok, false);
	});

	test('rejects a malformed uuid', () => {
		const result = parse(`vless://not-a-uuid@proxy.example.test:443?${BASE_PARAMS}`);
		assert.equal(result.ok, false);
	});
});
