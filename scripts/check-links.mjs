import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';

const files = ['README.md', ...readdirSync('docs').filter((name) => name.endsWith('.md')).map((name) => join('docs', name))];
let broken = 0;
for (const file of files) {
  const source = readFileSync(file, 'utf8');
  const regex = /\[[^\]]*\]\(([^)\s]+)\)/g;
  let match;
  while ((match = regex.exec(source))) {
    let target = match[1];
    if (/^(https?:|mailto:|#|\/)/i.test(target)) continue;
    target = target.split('#')[0];
    if (!target) continue;
    const resolved = resolve(dirname(file), target);
    if (!existsSync(resolved)) {
      broken += 1;
      console.log(`${file} -> ${target}`);
    }
  }
}
console.log(`broken links: ${broken}`);
