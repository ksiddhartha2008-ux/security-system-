#!/usr/bin/env node
/**
 * Astryx integration regression check. It does not render the application; it
 * verifies the pinned packages, the compiled theme and the wiring that would be
 * easy to lose in a refactor.
 */
import { readFileSync, existsSync } from 'node:fs';

const root = process.cwd();
const frontend = `${root}/frontend`;
const failures = [];
const check = (condition, message) => { if (!condition) failures.push(message); };
const read = (path) => (existsSync(path) ? readFileSync(path, 'utf8') : '');

const pkg = JSON.parse(read(`${frontend}/package.json`) || '{}');
const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
for (const name of ['@astryxdesign/core', '@astryxdesign/theme-neutral', '@astryxdesign/cli']) {
  const version = String(deps[name] ?? '').replace(/^[~^]/, '');
  check(version === '0.7.13', `${name} must be pinned to 0.7.13, found ${deps[name]}`);
}
const stylexVersion = String(deps['@stylexjs/stylex'] ?? '').replace(/^[~^]/, '');
check(stylexVersion === '0.19.1', `@stylexjs/stylex must be 0.19.1, found ${deps['@stylexjs/stylex']}`);
check(pkg.scripts?.['check:theme'], 'frontend package.json is missing check:theme');

const styles = read(`${frontend}/src/styles.css`);
for (const [needle, label] of [
  ['@astryxdesign/core/reset.css', 'Astryx reset import'],
  ['@astryxdesign/core/astryx.css', 'Astryx component CSS import'],
  ['./lib/theme/secureflow.css', 'SecureFlow theme CSS import'],
]) check(styles.includes(needle), `styles.css is missing ${label}`);

const themeCss = read(`${frontend}/src/lib/theme/secureflow.css`);
check(themeCss.includes('data-astryx-theme="secureflow"'), 'compiled theme is not scoped to secureflow');
for (const token of ['--color-accent', '--color-error', '--color-background-card', '--focus-outline-color']) {
  check(themeCss.includes(token), `compiled theme is missing ${token}`);
}

const app = read(`${frontend}/src/App.tsx`);
check(app.includes('AstryxProviders'), 'App.tsx is not wrapped in AstryxProviders');
check((app.match(/lazy\(\(\) => import/g) ?? []).length >= 15, 'module routes are not lazy loaded');

const layout = read(`${frontend}/src/components/layout.tsx`);
for (const symbol of ['AppShell', 'TopNav', 'SideNav', 'TopNavHeading', 'SideNavSection']) {
  check(layout.includes(symbol), `layout.tsx is missing ${symbol}`);
}

const ui = read(`${frontend}/src/components/ui.tsx`);
check(ui.includes("from '@astryxdesign/core/Badge'"), 'shared Badge is not using Astryx');
check(ui.includes("from '@astryxdesign/core/TextInput'"), 'shared SearchInput is not using Astryx');

const design = read(`${frontend}/src/components/design.tsx`);
check(design.includes("from '@astryxdesign/core/Card'"), 'MetricCard is not using Astryx Card');

if (failures.length) {
  console.error('Astryx integration check failed:');
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log('Astryx integration check passed: pinned packages, compiled theme, shell, shared components and lazy routes are wired.');
