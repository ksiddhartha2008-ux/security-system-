import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Minimal .env loader. The deployment passes real environment variables, but a
 * local checkout may use the ignored repository .env file. Existing environment
 * variables win. Values are never logged. Tests skip the file so a developer's
 * provider credentials cannot send real email during a test run.
 */
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..', '..');

if (process.env.NODE_ENV !== 'test' && process.env.SF_SKIP_ENV_FILE !== 'true') {
  const file = join(root, '.env');
  if (existsSync(file)) {
    let loaded = 0;
    for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const index = trimmed.indexOf('=');
      if (index <= 0) continue;
      const key = trimmed.slice(0, index).trim();
      let value = trimmed.slice(index + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
      if (process.env[key] !== undefined) continue;
      process.env[key] = value;
      loaded += 1;
    }
    if (loaded) console.log(`[env] loaded ${loaded} setting(s) from .env`);
  }
}
