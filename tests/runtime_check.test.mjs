import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftMany, readBackend, runUcodeJson } from './ucode_helper.mjs';

const ucode = findUcode();

describe('runtime_check', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const body = liftMany(readBackend(), ['tproxy_listening', 'check_runtime']);

	function runCheck(appearsAt, waitSeconds, { enabled = true, nftCode = 0 } = {}) {
		const stubs = `
let probes = 0;
function capture(command) {
	if (index(command, 'ss -H') >= 0) {
		probes++;
		return { code: 0, output: probes >= ${appearsAt}
			? 'tcp LISTEN 0 0 0.0.0.0:7893 users:(("xray",pid=1,fd=7))'
			: '' };
	}
	return { code: 0, output: '' };
}
function system(command) {
	if (index(command, 'zarap_killswitch_forward') >= 0 ||
		index(command, 'zarap_prerouting') >= 0)
		return ${nftCode};
	return 0;
}
`;
		return runUcodeJson(
			ucode,
			`${stubs}\n${body}\nprintf('%J', { health: check_runtime(${enabled ? 'true' : 'false'}, ${waitSeconds}), probes: probes });\n`
		);
	}

	test('waiting finds a listener that is still binding', () => {
		const result = runCheck(3, 5);
		assert.equal(result.health.listener, true);
		assert.equal(result.health.ok, true);
	});

	test('the same service fails the check without waiting', () => {
		const result = runCheck(3, 0);
		assert.equal(result.health.listener, false);
		assert.equal(result.health.ok, false);
		assert.equal(result.probes, 1);
	});

	test('an immediate listener costs no extra probe', () => {
		const result = runCheck(1, 5);
		assert.equal(result.health.listener, true);
		assert.equal(result.probes, 1);
	});

	test('the firewall state is reported with the proxy switched off', () => {
		const result = runCheck(99, 0, { enabled: false });
		assert.equal(result.health.firewall, true);
		assert.equal(result.health.running, false);
		assert.equal(result.health.routing, false);
	});

	test('a missing chain is reported with the proxy switched off', () => {
		const result = runCheck(99, 0, { enabled: false, nftCode: 1 });
		assert.equal(result.health.firewall, false);
	});

	test('waiting is bounded when the port never opens', () => {
		const result = runCheck(99, 3);
		assert.equal(result.health.listener, false);
		assert.equal(result.probes, 4);
	});
});
