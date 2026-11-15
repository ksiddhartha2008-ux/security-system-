import { test, expect } from '@playwright/test';

/**
 * Version skew regression: a server from an older build may omit a feature flag
 * in /auth/me. A missing field must degrade the affected entry, never blank the
 * whole application behind the error boundary.
 */
async function withStaleMe(page: import('@playwright/test').Page) {
  const response = await page.request.get('/api/auth/me');
  expect(response.ok()).toBeTruthy();
  const payload = await response.json();
  expect(payload.data.features.trishield).toBeTruthy();
  delete payload.data.features.trishield;
  await page.route('**/api/auth/me', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  }));
}

test('a server without the TriShield flag still renders the shell', async ({ page }) => {
  await withStaleMe(page);
  await page.goto('/overview');
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
  await expect(page.getByText('This view could not be rendered')).toHaveCount(0);
  await expect(page.getByRole('link', { name: /TriShield defense/ })).toHaveCount(0);
});

test('the TriShield route explains the missing flag instead of crashing', async ({ page }) => {
  await withStaleMe(page);
  await page.goto('/trishield');
  await expect(page.getByText('TriShield is turned off')).toBeVisible();
  await expect(page.getByText('This view could not be rendered')).toHaveCount(0);
});
