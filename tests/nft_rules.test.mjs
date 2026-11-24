import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import {
	execQuiet, findUcode, liftConstants, liftMany, readBackend, runUcode, whichBin
} from './ucode_helper.mjs';

const UBUS_STUB = `
function connect() {
	return {
		call: function(object, method) {
			return {
				'ipv4-address': [ { address: '192.168.10.1', mask: 24 } ],
				'ipv6-prefix': [ { address: 'fd00:abcd::', mask: 64 } ]
			};
		},
		disconnect: function() {}
	};
}
`;

const GUARDED = "[ '192.168.10.167', '192.168.10.42' ]";
const LAN = "'br-lan'";

function resolveNft() {
	const nft = whichBin('nft') || '/usr/sbin/nft';
	if (!existsSync(nft))
		return { skip: 'no nft binary available' };
	const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
	const prefix = isRoot ? [] : ['sudo', '-n'];
	if (prefix.length && !whichBin('sudo'))
		return { skip: 'nft needs privileges and sudo is absent' };
	const cmd = [...prefix, nft];
	const dir = mkdtempSync(join(tmpdir(), 'zarap-nft-'));
	const probe = join(dir, 'probe.nft');
	try {
		writeFileSync(probe, 'table inet zarap_probe {\n}\n', 'utf8');
		const done = execQuiet(cmd[0], [...cmd.slice(1), '-c', '-f', probe]);
		if (done.status !== 0)
			return { skip: `cannot run nft: ${(done.stderr || '').trim()}` };
		return { cmd };
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

const ucode = findUcode();
const nftInfo = ucode ? resolveNft() : { skip: 'no ucode interpreter available' };

describe('nft_rules', { skip: nftInfo.skip }, () => {
	const source = readBackend();
	const constants = liftConstants(source, ['const CAPTURE_PORT', 'const MARK ']);
	const prelude = `${UBUS_STUB}${constants}\n${liftMany(source, [
		'valid_ipv4', 'network_v4', 'v4_covered', 'nft_set', 'direct_networks', 'nft_config'
	])}`;
	const [nftBin, ...nftPrefix] = nftInfo.cmd;

	function runNft(args) {
		return execQuiet(nftBin, [...nftPrefix, ...args]);
	}

	function runNftFile(text, extraArgs = []) {
		const dir = mkdtempSync(join(tmpdir(), 'zarap-nft-'));
		const file = join(dir, 'rules.nft');
		try {
			writeFileSync(file, text, 'utf8');
			return runNft([...extraArgs, '-f', file]);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}

	function generate(guarded = GUARDED, proxying = 'true', lan = LAN) {
		return runUcode(ucode, `${prelude}\nprint(nft_config(${guarded}, ${lan}, ${proxying}));\n`);
	}

	function check(ruleset) {
		return runNftFile(`table inet zarap_check {\n${ruleset}}\n`, ['-c']);
	}

	test('nftables accepts the generated ruleset', () => {
		const done = check(generate());
		assert.equal(done.status, 0, done.stderr);
	});

	test('nftables accepts a ruleset with no guarded devices', () => {
		const done = check(generate('[]'));
		assert.equal(done.status, 0, done.stderr);
	});

	test('a set declaration does not clear an existing set', () => {
		const table = ['inet', 'zarap_selftest'];
		const populated =
			'table inet zarap_selftest {\n\tset clients {\n' +
			'\t\ttype ipv4_addr\n\t\telements = { 192.168.10.176 }\n\t}\n}\n';
		const declared =
			'table inet zarap_selftest {\n\tset clients {\n' +
			'\t\ttype ipv4_addr\n\t}\n}\n';

		function elements() {
			const done = runNft(['list', 'set', ...table, 'clients']);
			assert.equal(done.status, 0, done.stderr);
			return done.stdout;
		}

		runNft(['delete', 'table', ...table]);
		try {
			assert.equal(runNftFile(populated).status, 0);
			assert.ok(elements().includes('192.168.10.176'));
			assert.equal(runNftFile(declared).status, 0);
			assert.ok(elements().includes('192.168.10.176'),
				'nft cleared the set; the explicit flush may be redundant now');
			runNft(['flush', 'set', ...table, 'clients']);
			assert.ok(!elements().includes('192.168.10.176'));
		} finally {
			runNft(['delete', 'table', ...table]);
		}
	});

	test('the sync script is a valid nft transaction', () => {
		const stubs = `${UBUS_STUB}
let captured = '';
function writefile(path, text) { captured = text; return length(text); }
function capture(command) { print(captured); return { code: 0, output: '' }; }
function unlink(path) { return true; }
const NFT_SYNC = '/tmp/zarap-nft-sync.conf';
`;
		const rendered = runUcode(
			ucode,
			`${stubs}\n${liftMany(source, ['valid_ipv4', 'network_v4', 'v4_covered', 'direct_networks', 'sync_live_sets'])}\nsync_live_sets(${GUARDED});\n`
		);

		assert.ok(rendered.includes('flush set inet fw4 zarap_guarded_v4'));
		assert.ok(rendered.includes('192.168.10.167'));
		assert.ok(!rendered.includes('192.168.10.0/24'));

		const table = ['inet', 'zarap_selftest'];
		const setup =
			'table inet zarap_selftest {\n' +
			'\tset zarap_guarded_v4 { type ipv4_addr\n\t}\n' +
			'\tset zarap_direct_v4 { type ipv4_addr\n\t\tflags interval\n\t}\n' +
			'\tset zarap_direct_v6 { type ipv6_addr\n\t\tflags interval\n\t}\n}\n';

		runNft(['delete', 'table', ...table]);
		try {
			assert.equal(runNftFile(setup).status, 0);
			const done = runNftFile(rendered.replaceAll('inet fw4', 'inet zarap_selftest'));
			assert.equal(done.status, 0, done.stderr);
		} finally {
			runNft(['delete', 'table', ...table]);
		}
	});

	test('generated sets carry the guarded addresses', () => {
		const ruleset = generate();
		assert.ok(ruleset.includes('192.168.10.167'));
		assert.ok(!ruleset.includes('192.168.10.0/24'));
		assert.ok(ruleset.includes('192.168.0.0/16'));
	});

	test('tproxy and kill switch rules are present', () => {
		const ruleset = generate();
		assert.ok(ruleset.includes('iifname "br-lan" meta l4proto { tcp, udp }'));
		assert.ok(ruleset.includes('tproxy ip to 127.0.0.1:7893'));
		assert.ok(ruleset.includes('ip saddr @zarap_guarded_v4 reject'));
	});

	test('switching the proxy off keeps the kill switch', () => {
		const ruleset = generate(GUARDED, 'false');
		assert.ok(!ruleset.includes('tproxy ip to'));
		assert.ok(!ruleset.includes('meta mark set'));
		assert.ok(ruleset.includes('ip saddr @zarap_guarded_v4 reject'));
		assert.ok(ruleset.includes('192.168.10.167'));
		assert.equal(check(ruleset).status, 0);
	});

	test('capture does not depend on the guarded devices', () => {
		const prerouting = (ruleset) => ruleset.split('chain zarap_prerouting {')[1].split('}')[0];
		const empty = prerouting(generate('[]'));
		const one = prerouting(generate("[ '192.168.10.167' ]"));
		const many = prerouting(generate());
		assert.equal(empty, one);
		assert.equal(one, many);
	});

	test('ipv6 is barred for the whole lan', () => {
		for (const guarded of ['[]', GUARDED]) {
			const ruleset = generate(guarded);
			assert.ok(ruleset.includes('iifname "br-lan" ether type ip6 reject'));
			assert.ok(!ruleset.includes('ether saddr'));
			assert.ok(!ruleset.includes('zarap_guarded_mac'));
		}
	});

	test('an unguarded device is absent from the kill switch', () => {
		const ruleset = generate("[ '192.168.10.167' ]");
		assert.ok(ruleset.includes('192.168.10.167'));
		assert.ok(!ruleset.includes('192.168.10.42'));
	});
});
