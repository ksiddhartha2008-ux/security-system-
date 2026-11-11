import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installSnippet } from '../src/services/websiteSnippet.js';

const dir = mkdtempSync(join(tmpdir(), 'sf-snippet-'));

test.after(() => rmSync(dir, { recursive: true, force: true }));

test('the generated install snippet parses as an ES module', () => {
  const snippet = installSnippet({ hostname: 'shop.example.com' });
  assert.match(snippet, /new SecureFlow\(/);
  assert.match(snippet, /auth\.login_failed/);
  assert.match(snippet, /actorIdMode: 'hash'/);
  assert.match(snippet, /apiKey: process\.env\.SECUREFLOW_API_KEY/);
  const file = join(dir, 'snippet.mjs');
  writeFileSync(file, snippet, 'utf8');
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr);
});

test('the shipped SDK example parses as an ES module', () => {
  const file = join(process.cwd(), '..', 'packages', 'sdk-node', 'examples', 'login-route.mjs');
  const check = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  assert.equal(check.status, 0, check.stderr);
});

test('the SDK package is private, unlicensed for publication and dependency free', () => {
  const pkg = JSON.parse(readFileSync(join(process.cwd(), '..', 'packages', 'sdk-node', 'package.json'), 'utf8'));
  assert.equal(pkg.private, true);
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.engines.node, '>=24');
  assert.equal(pkg.exports['.'], './src/index.js');
});
