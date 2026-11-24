import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const ROOT = resolve(__dirname, '..');
export const PACKAGE_ROOT = join(ROOT, 'luci-app-zarap');
export const BACKEND_PATH = join(PACKAGE_ROOT, 'root/usr/share/rpcd/ucode/zarap.uc');
export const FIXTURES_DIR = join(__dirname, 'fixtures');

export function readBackend() {
	return readFileSync(BACKEND_PATH, 'utf8');
}

export function readFixture(name) {
	return readFileSync(join(FIXTURES_DIR, name), 'utf8');
}

export function findUcode() {
	if (process.env.UCODE_BIN && existsSync(process.env.UCODE_BIN))
		return process.env.UCODE_BIN;
	const which = spawnSync('which', ['ucode'], { encoding: 'utf8' });
	if (which.status === 0 && which.stdout.trim())
		return which.stdout.trim();
	if (existsSync('/tmp/ucode/build/ucode'))
		return '/tmp/ucode/build/ucode';
	return null;
}

/**
 * Extract one top-level function from zarap.uc by brace matching.
 */
export function lift(source, name) {
	const marker = `function ${name}(`;
	const start = source.indexOf(marker);
	assert.notEqual(start, -1, `function ${name} not found`);
	let depth = 0;
	for (let i = start; i < source.length; i++) {
		if (source[i] === '{') {
			depth++;
		} else if (source[i] === '}') {
			depth--;
			if (depth === 0)
				return source.slice(start, i + 1);
		}
	}
	assert.fail(`unterminated function ${name}`);
}

export function liftMany(source, names) {
	return names.map((name) => lift(source, name)).join('\n');
}

export function liftConstants(source, prefixes) {
	const lines = source.split('\n');
	const out = [];
	for (let i = 0; i < lines.length; i++) {
		if (!prefixes.some((prefix) => lines[i].startsWith(prefix)))
			continue;
		let line = lines[i];
		out.push(line);
		while (!line.trimEnd().endsWith(';') && i + 1 < lines.length) {
			i++;
			line = lines[i];
			out.push(line);
		}
	}
	return out.join('\n');
}

export function runUcode(ucodeBin, script) {
	const dir = mkdtempSync(join(tmpdir(), 'zarap-uc-'));
	const file = join(dir, 'script.uc');
	try {
		writeFileSync(file, script, 'utf8');
		const done = spawnSync(ucodeBin, [file], { encoding: 'utf8' });
		assert.equal(done.status, 0, done.stderr || `ucode exited with ${done.status}`);
		return done.stdout;
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

export function runUcodeJson(ucodeBin, script) {
	return JSON.parse(runUcode(ucodeBin, script));
}

export function whichBin(name) {
	const done = spawnSync('which', [name], { encoding: 'utf8' });
	return done.status === 0 ? done.stdout.trim() : null;
}

export function execQuiet(bin, args) {
	return spawnSync(bin, args, { encoding: 'utf8' });
}

export { execFileSync };
