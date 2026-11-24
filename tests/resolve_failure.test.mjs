import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, lift, readBackend, runUcodeJson } from './ucode_helper.mjs';

const UNRESOLVED =
	'2026/05/01 12:00:01 [Warning] [1234] app/proxyman/outbound: failed to process outbound traffic > ' +
	'proxy/vless/outbound: failed to find an available destination > ' +
	'common/retry: [dial tcp: lookup cdn1.aidar.one: i/o timeout]';

const UNRESOLVED_ON =
	'2026/05/01 12:00:01 [Warning] [1234] proxy/vless/outbound: dial tcp: ' +
	'lookup cdn1.aidar.one on 1.1.1.1:53: no such host';

const UNRESOLVED_APP_DNS =
	'2026/05/01 12:00:01 [Warning] app/dns: failed to lookup cdn1.aidar.one: context deadline exceeded';

const DEBUG_OK =
	'2026/05/01 12:00:01 [Debug] app/dns: lookup domain example.com\n' +
	'2026/05/01 12:00:01 [Debug] app/dns: lookup succeed for example.com: 104.20.23.154';

const HEALTHY =
	'2026/05/01 12:00:01 [Info] [1234] app/proxyman/inbound: connection accepted from 192.168.1.50:54321\n' +
	'2026/05/01 12:00:01 [Info] [1234] app/dispatcher: taking detour [out_3] for [tcp:1.2.3.4:443]';

const ucode = findUcode();

describe('resolve_failure', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const body = lift(readBackend(), 'recent_failures');

	function scan(log) {
		return runUcodeJson(
			ucode,
			`function capture(command) { return { code: 0, output: ${JSON.stringify(log)} }; }\n${body}\nprintf('%J', recent_failures());\n`
		);
	}

	test('a name that did not resolve is named', () => {
		assert.deepEqual(scan(UNRESOLVED), { connection: true, unresolved: 'cdn1.aidar.one' });
		assert.deepEqual(scan(UNRESOLVED_ON), { connection: true, unresolved: 'cdn1.aidar.one' });
		assert.deepEqual(scan(UNRESOLVED_APP_DNS), { connection: true, unresolved: 'cdn1.aidar.one' });
	});

	test('a successful lookup is not a failure', () => {
		assert.deepEqual(scan(DEBUG_OK), { connection: false, unresolved: '' });
	});

	test('a quiet log is quiet', () => {
		assert.deepEqual(scan(HEALTHY), { connection: false, unresolved: '' });
	});

	test('other failures are still caught but unnamed', () => {
		for (const line of [
			'2026/05/01 12:00:01 [Warning] reality handshake failed',
			'2026/05/01 12:00:01 [Warning] dial tcp 1.2.3.4:443: connection refused',
			'2026/05/01 12:00:01 [Warning] failed to process outbound traffic',
			'2026/05/01 12:00:01 [Warning] write: network is unreachable'
		]) {
			assert.deepEqual(scan(line), { connection: true, unresolved: '' }, line);
		}
	});

	test('the unresolved name wins over a generic marker', () => {
		assert.deepEqual(
			scan(UNRESOLVED),
			{ connection: true, unresolved: 'cdn1.aidar.one' }
		);
	});
});
