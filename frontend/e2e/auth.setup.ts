import { test as setup, expect } from '@playwright/test';

/**
 * One real sign in for the whole run. The login route is rate limited to twelve
 * attempts per fifteen minutes per address, so every spec reuses this state.
 */
setup('sign in as the demo administrator', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Administrator' }).click();
  await page.getByRole('button', { name: 'Continue to console' }).click();
  await expect(page).toHaveURL(/\/overview/);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.context().storageState({ path: 'e2e/.auth/admin.json' });
});
