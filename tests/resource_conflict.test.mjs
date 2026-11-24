import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftMany, readBackend, readFixture, runUcodeJson } from './ucode_helper.mjs';

const ucode = findUcode();

describe('resource_conflict', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const body = liftMany(source, ['result_error', 'resource_conflict']);

	function runConflict(ruleset) {
		const stubs = `
function capture(command) {
	if (index(command, 'list chain inet fw4 zarap_prerouting') >= 0)
		return { code: 0, output: ${JSON.stringify(readFixture('nft-chain-prerouting.txt'))} };
	if (index(command, 'list chain inet fw4 zarap_protect_tproxy') >= 0)
		return { code: 0, output: ${JSON.stringify(readFixture('nft-chain-protect.txt'))} };
	if (index(command, 'list ruleset') >= 0)
		return { code: 0, output: ${JSON.stringify(ruleset)} };
	return { code: 0, output: '' };
}
function saved_outbounds() { return [{ server: 'proxy.example.test' }]; }
`;
		return runUcodeJson(ucode, `${stubs}\n${body}\nprintf('%J', resource_conflict());\n`);
	}

	test('zarap own rules are not a conflict', () => {
		const result = runConflict(readFixture('nft-ruleset-clean.txt'));
		assert.equal(result.ok, true, result.error);
	});

	test('a foreign rule using the mark is reported', () => {
		const result = runConflict(readFixture('nft-ruleset-foreign.txt'));
		assert.equal(result.ok, false);
		assert.match(result.error, /0x5a52/);
	});

	test('the fixtures carry the padded form nft emits', () => {
		const clean = readFixture('nft-ruleset-clean.txt');
		assert.ok(clean.includes('0x00005a52'));
		assert.ok(!clean.includes('mark set 0x5a52 '));
	});
});
