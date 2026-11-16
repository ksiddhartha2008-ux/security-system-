import { test as setup, expect } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { totp } from './totp';

/**
 * One real sign in for the whole run. The login route is rate limited to twelve
 * attempts per fifteen minutes per address, so every spec reuses this state.
 *
 * Administrator-only mutations require an enrolled second factor, so this setup
 * enrols the demo administrator through the real API and stores the secret for
 * the one spec that signs in through the UI again.
 */
setup('sign in as the demo administrator', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Administrator' }).click();
  await page.getByRole('button', { name: 'Continue to console' }).click();
  await expect(page).toHaveURL(/\/overview/);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

  const me = await page.request.get('/api/auth/me');
  expect(me.ok()).toBeTruthy();
  const meBody = await me.json();
  if (!meBody.data.user.mfaEnabled) {
    const csrf = (await page.context().cookies()).find((cookie) => cookie.name === 'sf_csrf')?.value;
    expect(csrf, 'csrf cookie').toBeTruthy();
    const start = await page.request.post('/api/auth/mfa/setup', {
      headers: { 'x-csrf-token': csrf as string },
      data: { password: 'Admin#2026' },
    });
    expect(start.ok(), await start.text()).toBeTruthy();
    const { secret } = (await start.json()).data;
    const enable = await page.request.post('/api/auth/mfa/enable', {
      headers: { 'x-csrf-token': csrf as string },
      data: { code: totp(secret) },
    });
    expect(enable.ok(), await enable.text()).toBeTruthy();
    mkdirSync('e2e/.auth', { recursive: true });
    writeFileSync('e2e/.auth/admin-mfa.json', JSON.stringify({ secret }), 'utf8');
  }

  await page.context().storageState({ path: 'e2e/.auth/admin.json' });
});
