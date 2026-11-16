import { test, expect } from '@playwright/test';

/**
 * Public entry and authentication journey.
 *
 * These tests start signed out on purpose: the shared suite signs in once as the
 * administrator, but the landing page and the redirects belong to the public
 * surface and must be proven without a session.
 */
test.use({ storageState: { cookies: [], origins: [] } });

test('the root is the public landing page with working entry links', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    // Signed out pages probe /auth/me and /demo/status, so a 401 resource entry
    // is expected. Anything else is a real console error.
    if (message.type() === 'error' && !/Failed to load resource.*401/.test(message.text())) errors.push(message.text());
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('See the signal');
  await expect(page.getByRole('link', { name: 'Sign in' }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Create account' }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: /Three layers/ })).toBeVisible();
  await expect(page.locator('.reveal').first()).toBeVisible();

  await page.getByRole('link', { name: 'Sign in' }).first().click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByRole('heading', { level: 1, name: 'SecureFlow AI' })).toBeVisible();

  await page.goto('/');
  await page.getByRole('link', { name: 'Create account' }).first().click();
  await expect(page).toHaveURL(/\/signup/);
  await expect(page.getByRole('heading', { level: 1, name: 'Create a workspace' })).toBeVisible();

  await page.goto('/register');
  await expect(page).toHaveURL(/\/signup/);

  // No horizontal overflow on a phone viewport.
  await page.goto('/');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, 'landing page horizontal overflow at 390px').toBeLessThanOrEqual(1);
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();

  expect(errors, 'runtime errors on the public pages').toEqual([]);
});

test('a protected route sends a signed out visitor to sign in and back after login', async ({ page }) => {
  await page.goto('/overview');
  await expect(page).toHaveURL(/\/login\?next=%2Foverview/);

  await page.getByRole('button', { name: 'Continue to console' }).click({ timeout: 15_000 });
  await expect(page).toHaveURL(/\/overview/);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

  // A refresh keeps the session.
  await page.reload();
  await expect(page).toHaveURL(/\/overview/);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

  // The dashboard alias resolves to the existing route.
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/\/overview/);

  // TriShield is reachable inside the shell.
  await page.goto('/trishield');
  await expect(page.getByRole('heading', { level: 1, name: 'TriShield defense' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Integrations' })).toBeVisible();

  // An authenticated visitor still sees the public landing page at the root.
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('See the signal');
  await expect(page.getByRole('link', { name: 'Open the workspace' }).first()).toBeVisible();
});

test('an unknown route renders the not found page', async ({ page }) => {
  await page.goto('/this-route-does-not-exist');
  await expect(page.getByRole('heading', { level: 1, name: 'That page does not exist' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Back to home' })).toBeVisible();
});
