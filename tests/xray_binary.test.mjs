import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
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

function encodeDnsQuery(id, name, qtype) {
	const header = Buffer.alloc(12);
	header.writeUInt16BE(id, 0);
	header.writeUInt16BE(0x0100, 2); // RD=1
	header.writeUInt16BE(1, 4); // QDCOUNT=1
	const labels = [];
	for (const part of name.split('.')) {
		const buf = Buffer.from(part, 'ascii');
		labels.push(Buffer.from([buf.length]), buf);
	}
	labels.push(Buffer.from([0]));
	const tail = Buffer.alloc(4);
	tail.writeUInt16BE(qtype, 0);
	tail.writeUInt16BE(1, 2); // IN
	return Buffer.concat([header, ...labels, tail]);
}

function parseDnsQuestion(msg) {
	let offset = 12;
	const labels = [];
	while (offset < msg.length && msg[offset] !== 0) {
		const len = msg[offset++];
		labels.push(msg.subarray(offset, offset + len).toString('ascii'));
		offset += len;
	}
	offset += 1;
	const qtype = msg.readUInt16BE(offset);
	return { name: labels.join('.'), qtype, end: offset + 4 };
}

function buildDnsResponse(query, { ip = '198.51.100.1', txt = 'ok-via-tunnel' } = {}) {
	const q = parseDnsQuestion(query);
	const header = Buffer.alloc(12);
	query.copy(header, 0, 0, 2); // ID
	header.writeUInt16BE(0x8180, 2); // QR=1, RD=1, RA=1, NOERROR
	header.writeUInt16BE(1, 4); // QDCOUNT=1
	header.writeUInt16BE(1, 6); // ANCOUNT=1
	const question = query.subarray(12, q.end);
	let rdata;
	if (q.qtype === 1) {
		rdata = Buffer.from(ip.split('.').map(Number));
	} else {
		const bytes = Buffer.from(txt, 'ascii');
		rdata = Buffer.concat([Buffer.from([bytes.length]), bytes]);
	}
	const rr = Buffer.alloc(12);
	rr.writeUInt16BE(0xc00c, 0); // pointer to question name
	rr.writeUInt16BE(q.qtype, 2);
	rr.writeUInt16BE(1, 4); // IN
	rr.writeUInt32BE(60, 6); // TTL
	rr.writeUInt16BE(rdata.length, 10);
	return Buffer.concat([header, question, rr, rdata]);
}

function freeUdpPort() {
	return new Promise((resolve, reject) => {
		const sock = dgram.createSocket('udp4');
		sock.once('error', reject);
		sock.bind(0, '127.0.0.1', () => {
			const { port } = sock.address();
			sock.close(() => resolve(port));
		});
	});
}

function sendUdpDns(port, name, qtype) {
	return new Promise((resolve, reject) => {
		const sock = dgram.createSocket('udp4');
		const timer = setTimeout(() => {
			sock.close();
			reject(new Error(`DNS timeout for ${name} qtype=${qtype}`));
		}, 4000);
		sock.once('message', (msg) => {
			clearTimeout(timer);
			sock.close();
			resolve({
				rcode: msg.readUInt16BE(2) & 0x0f,
				ancount: msg.readUInt16BE(6),
				raw: msg
			});
		});
		sock.once('error', (err) => {
			clearTimeout(timer);
			sock.close();
			reject(err);
		});
		sock.send(encodeDnsQuery(Math.floor(Math.random() * 65535), name, qtype), port, '127.0.0.1');
	});
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
		'parse_tunnel_dns', 'outbound_json', 'dns_routes', 'dns_domain_tags',
		'xray_domains', 'url_hostname', 'geodata_cron', 'asset_filename',
		'ruleset_plan', 'rule_jsons', 'xray_config'
	])}`;

	function generate(outbounds, rules, final, {
		rulesets = [],
		rulesetDetour = 'direct',
		rulesetInterval = '1d',
		bootstrap = '',
		resolveAll = false,
		tunnelDns = '',
		skipAssets = null
	} = {}) {
		return runUcodeJson(
			ucode,
			`${prelude}\nprintf('%J', xray_config(${JSON.stringify(outbounds)}, ${JSON.stringify(rules)}, ${JSON.stringify(final)}, ${JSON.stringify(ADDRESSES)}, ${JSON.stringify(rulesets)}, ${JSON.stringify(rulesetDetour)}, ${JSON.stringify(bootstrap)}, ${resolveAll ? 'true' : 'false'}, ${JSON.stringify(tunnelDns)}, ${JSON.stringify(skipAssets)}, ${JSON.stringify(rulesetInterval)}));\n`
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

	test('multi-outbound domain routing with resolve_all=false (per-outbound dns-out) passes xray run -test', () => {
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

	test('resolve_all=true with DoH bootstrap and multi-outbound listeners passes xray run -test', () => {
		const config = generate(
			[OUT_1, OUT_2],
			[
				{ domains: ['youtube.com'], target: 'out_1' },
				{ domains: ['example.com'], target: 'out_2' }
			],
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
				rulesets: [{ tag: 'rs_1', url: 'https://example.org/geosite.dat', kind: 'geosite', category: 'youtube' }],
				rulesetDetour: 'out_1',
				resolveAll: true,
				bootstrap: 'https://1.1.1.1/dns-query',
				skipAssets: { [geosite]: true }
			}
		);
		checkWithXray(config);
	});

	test('live xray resolves A via bootstrap/tunnel and returns real TXT answers via dialerProxy without leaks', async () => {
		const bootSeen = [];
		const tunSeen = [];

		const bootServer = dgram.createSocket('udp4');
		bootServer.on('message', (msg, rinfo) => {
			const q = parseDnsQuestion(msg);
			bootSeen.push(`${q.name}:${q.qtype}`);
			bootServer.send(buildDnsResponse(msg, { ip: '198.51.100.1', txt: 'from-boot' }), rinfo.port, rinfo.address);
		});
		await new Promise((resolve) => bootServer.bind(0, '127.0.0.1', resolve));
		const bootPort = bootServer.address().port;

		const tunServer = net.createServer((socket) => {
			let buf = Buffer.alloc(0);
			socket.on('data', (chunk) => {
				buf = Buffer.concat([buf, chunk]);
				while (buf.length >= 2) {
					const len = buf.readUInt16BE(0);
					if (buf.length < 2 + len)
						break;
					const msg = buf.subarray(2, 2 + len);
					buf = buf.subarray(2 + len);
					const q = parseDnsQuestion(msg);
					tunSeen.push(`${q.name}:${q.qtype}`);
					const resp = buildDnsResponse(msg, { ip: '203.0.113.1', txt: 'ok-via-tunnel' });
					const framed = Buffer.alloc(2 + resp.length);
					framed.writeUInt16BE(resp.length, 0);
					resp.copy(framed, 2);
					socket.write(framed);
				}
			});
		});
		await new Promise((resolve) => tunServer.listen(0, '127.0.0.1', resolve));
		const tunPort = tunServer.address().port;

		const listenPort = await freeUdpPort();
		const config = generate(
			[OUT_1],
			[{ domains: ['tun.example'], target: 'out_1' }],
			'direct',
			{
				resolveAll: true,
				bootstrap: `udp://127.0.0.1:${bootPort}`,
				tunnelDns: `tcp://127.0.0.1:${tunPort}`
			}
		);
		// Keep generated DNS, routing, and dns-out untouched; only drop TProxy
		// (needs CAP_NET_ADMIN), swap out_1 to freedom, and bind an ephemeral port.
		config.inbounds = config.inbounds
			.filter((i) => i.tag !== 'zarap-tproxy')
			.map((i) => ({ ...i, port: listenPort }));
		config.outbounds = config.outbounds.map((o) => (
			o.tag === 'out_1' ? { tag: 'out_1', protocol: 'freedom' } : o
		));

		const dir = mkdtempSync(join(tmpdir(), 'zarap-xray-live-'));
		const cfgPath = join(dir, configTmpName);
		writeFileSync(cfgPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
		const proc = spawn(xray, ['run', '-c', cfgPath], {
			stdio: ['ignore', 'pipe', 'pipe'],
			env: { ...process.env, XRAY_LOCATION_ASSET: dir }
		});
		let stderr = '';
		proc.stderr.on('data', (d) => { stderr += d.toString(); });
		try {
			await new Promise((resolve, reject) => {
				const timer = setTimeout(() => reject(new Error(`xray did not start:\n${stderr}`)), 4000);
				const onData = (chunk) => {
					if (chunk.toString().includes('started')) {
						clearTimeout(timer);
						resolve();
					}
				};
				proc.stdout.on('data', onData);
				proc.stderr.on('data', onData);
				proc.once('exit', (code) => {
					clearTimeout(timer);
					reject(new Error(`xray exited early (${code}):\n${stderr}`));
				});
			});

			const directA = await sendUdpDns(listenPort, 'direct.example', 1);
			assert.equal(directA.rcode, 0);
			assert.equal(directA.ancount, 1);

			const tunA = await sendUdpDns(listenPort, 'tun.example', 1);
			assert.equal(tunA.rcode, 0);
			assert.equal(tunA.ancount, 1);

			// TXT for tunnel domain must return a real answer through the tunnel,
			// never a fabricated empty NOERROR and never leaking to bootstrap.
			const tunTxt = await sendUdpDns(listenPort, 'tun.example', 16);
			assert.equal(tunTxt.rcode, 0);
			assert.equal(tunTxt.ancount, 1, 'tunnel TXT query must return answer, not empty NOERROR');
			assert.ok(tunTxt.raw.includes(Buffer.from('ok-via-tunnel')));

			// TXT for non-tunnel domain must also traverse the tunnel (never
			// downgraded to plaintext UDP/53 on the bootstrap resolver).
			const directTxt = await sendUdpDns(listenPort, 'direct.example', 16);
			assert.equal(directTxt.rcode, 0);
			assert.equal(directTxt.ancount, 1);
			assert.ok(directTxt.raw.includes(Buffer.from('ok-via-tunnel')));

			assert.deepEqual(bootSeen, ['direct.example:1']);
			assert.ok(tunSeen.includes('tun.example:1'), `tunSeen=${JSON.stringify(tunSeen)}`);
			assert.ok(tunSeen.includes('tun.example:16'), `tunSeen=${JSON.stringify(tunSeen)}`);
			assert.ok(tunSeen.includes('direct.example:16'), `tunSeen=${JSON.stringify(tunSeen)}`);
		} finally {
			proc.kill('SIGTERM');
			await new Promise((resolve) => proc.once('exit', resolve));
			await new Promise((resolve) => bootServer.close(resolve));
			await new Promise((resolve) => tunServer.close(resolve));
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
