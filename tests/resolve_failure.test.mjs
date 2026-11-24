import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, lift, readBackend, runUcodeJson } from './ucode_helper.mjs';

const UNRESOLVED =
	'ERROR [1234 10.0s] connection: open connection to 198.18.0.21:443 using ' +
	'outbound/vless[out_4]: lookup cdn1.aidar.one: context deadline exceeded';

const LOOP =
	'ERROR [1234 4.6s] connection: open connection to 198.18.0.21:443 using ' +
	'outbound/vless[out_4]: lookup cdn1.aidar.one: DNS query loopback in ' +
	'transport[dns_out_4]';

const DEBUG_OK =
	'DEBUG [1234 0ms] dns: lookup domain example.com\n' +
	'DEBUG [1234 16ms] dns: lookup succeed for example.com: 104.20.23.154';

const HEALTHY =
	'INFO [1234 0ms] inbound/tproxy[zarap-tproxy]: inbound connection to 1.2.3.4:443\n' +
	'INFO [1234 3ms] outbound/vless[out_3]: outbound connection to 1.2.3.4:443';

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
		assert.deepEqual(scan(LOOP), { connection: true, unresolved: 'cdn1.aidar.one' });
	});

	test('a successful lookup is not a failure', () => {
		assert.deepEqual(scan(DEBUG_OK), { connection: false, unresolved: '' });
	});

	test('a quiet log is quiet', () => {
		assert.deepEqual(scan(HEALTHY), { connection: false, unresolved: '' });
	});

	test('other failures are still caught but unnamed', () => {
		for (const line of [
			'ERROR reality handshake failed',
			'ERROR dial tcp 1.2.3.4:443: connection refused',
			'ERROR write: network is unreachable'
		]) {
			assert.deepEqual(scan(line), { connection: true, unresolved: '' }, line);
		}
	});

	test('the unresolved name wins over a generic marker', () => {
		assert.deepEqual(
			scan(UNRESOLVED.replace('context deadline exceeded', 'i/o timeout')),
			{ connection: true, unresolved: 'cdn1.aidar.one' }
		);
	});
});
