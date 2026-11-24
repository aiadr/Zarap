import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { findUcode, liftMany, readBackend, readFixture, runUcodeJson } from './ucode_helper.mjs';

const ucode = findUcode();

describe('resource_conflict', { skip: !ucode && 'no ucode interpreter available' }, () => {
	const source = readBackend();
	const body = liftMany(source, ['result_error', 'legacy_zarap_sing_box', 'resource_conflict']);

	function runConflict(ruleset, { listeners = '', legacySingBox = null } = {}) {
		const uciValues = legacySingBox || {};
		const stubs = `
function capture(command) {
	if (index(command, 'ss -H') >= 0)
		return { code: 0, output: ${JSON.stringify(listeners)} };
	if (index(command, 'list chain inet fw4 zarap_prerouting') >= 0)
		return { code: 0, output: ${JSON.stringify(readFixture('nft-chain-prerouting.txt'))} };
	if (index(command, 'list chain inet fw4 zarap_protect_tproxy') >= 0)
		return { code: 0, output: ${JSON.stringify(readFixture('nft-chain-protect.txt'))} };
	if (index(command, 'list ruleset') >= 0)
		return { code: 0, output: ${JSON.stringify(ruleset)} };
	return { code: 0, output: '' };
}
function saved_outbounds() { return [{ server: 'proxy.example.test' }]; }
function cursor() {
	let data = ${JSON.stringify(uciValues)};
	return {
		load: function() {},
		get: function(pkg, sec, opt) { return data[pkg + '.' + sec + '.' + opt]; }
	};
}
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

	test('legacy Zarap sing-box on port 7893 is recognized for migration', () => {
		const result = runConflict(readFixture('nft-ruleset-clean.txt'), {
			listeners: 'tcp LISTEN 0 0 0.0.0.0:7893 users:(("sing-box",pid=1,fd=7))',
			legacySingBox: {
				'sing-box.main.conffile': '/etc/zarap/sing-box.json',
				'sing-box.main.enabled': '1'
			}
		});
		assert.equal(result.ok, true, result.error);
	});

	test('a foreign sing-box (e.g. Podkop) on port 7893 is still refused', () => {
		const result = runConflict(readFixture('nft-ruleset-clean.txt'), {
			listeners: 'tcp LISTEN 0 0 0.0.0.0:7893 users:(("sing-box",pid=2,fd=7))',
			legacySingBox: {
				'sing-box.main.conffile': '/etc/sing-box/config.json',
				'sing-box.main.enabled': '1'
			}
		});
		assert.equal(result.ok, false);
		assert.match(result.error, /7893/);
	});
});
