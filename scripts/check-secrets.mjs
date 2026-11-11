#!/usr/bin/env node
/**
 * Repository secret scan. Fails the build when a website key, a private key
 * block or an AWS access key id is found in a tracked file.
 * Run with: node scripts/check-secrets.mjs
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const root = process.cwd();
const skip = new Set(['.git', 'node_modules', 'dist', 'data', '.zwork']);
const textExtensions = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.json', '.jsonc', '.md', '.yml', '.yaml',
  '.sql', '.css', '.html', '.txt', '.example', '.ps1', '.sh', '.toml', '',
]);

const patterns = [
  { name: 'website key', regex: /sfk_[a-z2-7]{12}_[A-Za-z0-9_-]{43}/g },
  { name: 'private key block', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'AWS access key id', regex: /\bAKIA[0-9A-Z]{16}\b/g },
];

const findings = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.env' || entry.name.startsWith('.env.')) continue;
    if (entry.isDirectory()) {
      if (skip.has(entry.name)) continue;
      walk(join(dir, entry.name));
      continue;
    }
    const full = join(dir, entry.name);
    const ext = extname(entry.name).toLowerCase();
    if (!textExtensions.has(ext)) continue;
    let text;
    try {
      if (statSync(full).size > 2 * 1024 * 1024) continue;
      text = readFileSync(full, 'utf8');
    } catch {
      continue;
    }
    for (const pattern of patterns) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(text))) {
        const line = text.slice(0, match.index).split('\n').length;
        findings.push({ file: full.slice(root.length + 1), line, type: pattern.name });
      }
    }
  }
}

walk(root);

if (findings.length) {
  console.error('Secret scan failed. Remove the value from the repository and rotate it.');
  for (const finding of findings) console.error(`  ${finding.file}:${finding.line} ${finding.type}`);
  process.exit(1);
}
console.log('Secret scan clean: no website key, private key block or AWS access key id found.');
