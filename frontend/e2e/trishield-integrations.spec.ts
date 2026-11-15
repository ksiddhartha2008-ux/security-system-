import { test, expect } from '@playwright/test';

/**
 * Integration Setup Center. Every integration must show its configuration,
 * connection and verification state, the missing requirements, and a real test
 * action. Nothing here is allowed to claim health from configuration alone.
 */
test('the setup center lists every integration with its state and setup steps', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });

  await page.goto('/trishield');
  await page.getByRole('tab', { name: 'Integrations' }).click();

  await expect(page.getByRole('heading', { name: 'Linux nftables' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'ClamAV scanner' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Test connection' })).toHaveCount(6);
  await expect(page.getByText('A configured variable alone is never shown as healthy.')).toBeVisible();

  await page.getByText('Setup steps').first().click();
  await expect(page.getByText('Windows', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Linux', { exact: true }).first()).toBeVisible();

  expect(errors, 'runtime errors on the setup center').toEqual([]);
});

test('a real check with no scanner records not configured instead of healthy', async ({ page }) => {
  await page.goto('/trishield');
  await page.getByRole('tab', { name: 'Integrations' }).click();

  const card = page.locator('.card', { has: page.getByRole('heading', { name: 'ClamAV scanner' }) });
  await card.getByRole('button', { name: 'Test connection' }).click();
  await expect(card.getByText(/CLAMAV_HOST is not set/)).toBeVisible({ timeout: 15_000 });
  await expect(card.getByText(/Last check/)).not.toContainText('never');
});
