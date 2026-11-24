import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { describe, test } from 'node:test';
import { findUcode, liftConstants, liftMany, readBackend, runUcodeJson, whichBin } from './ucode_helper.mjs';

function findXray() {
	if (process.env.XRAY_BIN && existsSync(process.env.XRAY_BIN))
		return process.env.XRAY_BIN;
	const fromPath = whichBin('xray');
	if (fromPath)
		return fromPath;
	if (existsSync('/tmp/xray-bin/xray'))
		return '/tmp/xray-bin/xray';
	if (existsSync('/tmp/xray/xray'))
		return '/tmp/xray/xray';
	return null;
}

const ucode = findUcode();
const xray = findXray();

// Valid 43-char base64url X25519 public key (generated via `xray x25519`).
const OUT_1 = {
	tag: 'out_1',
	server: 'nl.example.test',
	server_port: 443,
	uuid: '123e4567-e89b-42d3-a456-426614174000',
	flow: 'xtls-rprx-vision',
	server_name: 'cdn.example.test',
	public_key: 'nvR6cEULqSpLS5Ftsx08RT9RN-bFkA0mzUIEGMDOyik',
	short_id: 'a1b2',
	fingerprint: 'chrome'
};

const OUT_2 = { ...OUT_1, tag: 'out_2', server: '203.0.113.10', flow: '', short_id: '' };

const ADDRESSES = {
	'00:11:22:33:44:55': '192.168.1.50',
	'AA:BB:CC:DD:EE:FF': '192.168.1.51'
};

describe('xray_binary_validation', {
	skip: (!ucode && 'no ucode interpreter available') || (!xray && 'no xray binary available')
}, () => {
	const source = readBackend();
	const configTmpMatch = source.match(/const CONFIG_TMP = '([^']+)'/);
	const configTmpName = basename(configTmpMatch ? configTmpMatch[1] : '.xray.tmp.json');

	const constants = liftConstants(source, [
		'const CAPTURE_PORT', 'const INBOUND_TAG', 'const RESERVED_TAGS',
		'const DNS_TAG', 'const DNS_PORT', 'const DNS_OUT_TAG',
		'const DNS_UPSTREAM', 'const BOOTSTRAP_TAG', 'const BOOTSTRAP_DEFAULT',
		'const BOOTSTRAP_SCHEMES', 'const TUNNEL_DEFAULT'
	]);
	const prelude = `${constants}\n${liftMany(source, [
		'valid_outbound_tag', 'valid_ipv4', 'is_domain', 'result_error',
		'input_error', 'parse_resolver', 'xray_dns_server', 'parse_bootstrap',
		'parse_tunnel_dns', 'outbound_json', 'dns_routes', 'xray_domains',
		'url_hostname', 'geodata_cron', 'asset_filename', 'ruleset_plan',
		'rule_jsons', 'xray_config'
	])}`;

	function generate(outbounds, rules, final, {
		rulesets = [],
		rulesetDetour = 'direct',
		bootstrap = '',
		resolveAll = false,
		tunnelDns = '',
		skipAssets = null
	} = {}) {
		return runUcodeJson(
			ucode,
			`${prelude}\nprintf('%J', xray_config(${JSON.stringify(outbounds)}, ${JSON.stringify(rules)}, ${JSON.stringify(final)}, ${JSON.stringify(ADDRESSES)}, ${JSON.stringify(rulesets)}, ${JSON.stringify(rulesetDetour)}, ${JSON.stringify(bootstrap)}, ${resolveAll ? 'true' : 'false'}, ${JSON.stringify(tunnelDns)}, ${JSON.stringify(skipAssets)}));\n`
		);
	}

	function assetFile(url) {
		return runUcodeJson(ucode, `${prelude}\nprintf('%J', asset_filename(${JSON.stringify(url)}));\n`);
	}

	function checkWithXray(config, assetFiles = []) {
		const dir = mkdtempSync(join(tmpdir(), 'zarap-xray-'));
		try {
			for (const name of assetFiles)
				writeFileSync(join(dir, name), '', 'utf8');
			// Write using the exact basename of CONFIG_TMP (e.g. .xray.tmp.json)
			// so a bad extension regression fails here just like on the router.
			const cfgPath = join(dir, configTmpName);
			writeFileSync(cfgPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
			const done = spawnSync(xray, ['run', '-test', '-c', cfgPath], {
				encoding: 'utf8',
				env: { ...process.env, XRAY_LOCATION_ASSET: dir }
			});
			const output = `${done.stdout || ''}\n${done.stderr || ''}`;
			assert.equal(done.status, 0, output);
			assert.match(output, /Configuration OK/);
			assert.equal(output.toLowerCase().includes('deprecated'), false, `unexpected deprecation warning:\n${output}`);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}

	test('minimal VLESS Reality TCP config passes xray run -test at CONFIG_TMP path', () => {
		const config = generate([OUT_1], [{ clients: ['00:11:22:33:44:55'], target: 'out_1' }], 'direct');
		checkWithXray(config);
	});

	test('domain routing with resolve_all=false (dialerProxy dns-out) passes xray run -test', () => {
		const config = generate(
			[OUT_1, OUT_2],
			[
				{ domains: ['youtube.com', '.googlevideo.com'], target: 'out_1' },
				{ domains: ['example.com'], ports: ['443', '1000:2000'], network: 'tcp', target: 'out_2' },
				{ ip_cidr: ['149.154.160.0/20'], target: 'block' }
			],
			'direct',
			{ bootstrap: 'udp://192.168.1.1', tunnelDns: 'https://1.1.1.1/dns-query' }
		);
		checkWithXray(config);
	});

	test('resolve_all=true with DoH bootstrap and non-IP rules passes xray run -test', () => {
		const config = generate(
			[OUT_1],
			[{ domains: ['youtube.com'], target: 'out_1' }],
			'direct',
			{ resolveAll: true, bootstrap: 'https://77.88.8.8/dns-query', tunnelDns: 'tcp://9.9.9.9' }
		);
		checkWithXray(config);
	});

	test('dry-run validate with skip_assets passes xray run -test without .dat files on disk', () => {
		const geosite = assetFile('https://example.org/geosite.dat');
		const config = generate(
			[OUT_1],
			[{ domains: ['example.com'], rule_sets: ['rs_1'], target: 'out_1' }],
			'direct',
			{
				rulesets: [{ tag: 'rs_1', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'youtube', update_interval: '1d' }],
				rulesetDetour: 'out_1',
				resolveAll: true,
				bootstrap: 'https://1.1.1.1/dns-query',
				skipAssets: { [geosite]: true }
			}
		);
		checkWithXray(config);
	});
});
