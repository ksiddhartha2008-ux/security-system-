import { test, expect } from '@playwright/test';

/**
 * Phase 1.3 gate, exercised through the real UI. The API level suite covers the
 * successful token exchange; this spec proves the browser never renders the
 * workspace for an unverified account and that the public verification page
 * reports a rejected link without leaking anything.
 */
test.describe('email ownership gate', () => {
  // The shared project state is the signed in demo administrator; this spec
  // needs a signed out browser so it can create and use its own account.
  test.use({ storageState: { cookies: [], origins: [] } });
  test('a new account lands on the pending screen instead of the workspace', async ({ page }) => {
    const email = `e2e-verify-${Date.now()}@example.test`;
    const password = 'Anchor#2026';

    await page.goto('/signup');
    await expect(page.getByRole('heading', { level: 1, name: 'Create a workspace' })).toBeVisible();
    await page.locator('#org').fill('Gate Workspace');
    await page.locator('#name').fill('Gate User');
    await expect(page.locator('#signup-email')).toBeVisible();
    await page.locator('#signup-email').fill(email);
    await page.locator('#signup-password').fill(password);
    await page.getByRole('button', { name: 'Create workspace' }).click();

    await expect(page).toHaveURL(/\/login\?registered=1/);
    await expect(page.getByText('If registration can be completed, check your email to verify the address, then sign in.')).toBeVisible();

    // The console offers demo accounts by default, so switch to the credential form.
    const switchAccount = page.getByRole('button', { name: 'Sign in with another account' });
    if (await switchAccount.isVisible()) await switchAccount.click();

    await page.locator('#email').fill(email);
    await page.locator('#password').fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Verify your email' })).toBeVisible();
    await expect(page.getByText(email)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Resend email' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

    // The workspace shell, including navigation, must not be mounted.
    await expect(page.getByRole('link', { name: 'Overview' })).toHaveCount(0);

    await page.getByRole('button', { name: 'Resend email' }).click();
    await expect(page.getByRole('status')).toContainText('If this account needs verification, a new message will be sent.');

    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login/);

    await page.goto('/overview');
    await expect(page).toHaveURL(/\/login\?next=%2Foverview/);
  });

  test('the verification page reports success when the API accepts the link', async ({ page }) => {
    await page.route('**/api/auth/verify-email', (route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ data: { verified: true } }),
    }));
    await page.goto('/verify-email?token=accepted-token-value-0000000000');
    await expect(page.getByText('Email verified')).toBeVisible();
    await expect(page.getByText('Your email is verified. Sign in to open the workspace.')).toBeVisible();
  });

  test('the verification page rejects a link without a usable token', async ({ page }) => {
    await page.goto('/verify-email?token=not-a-real-token-value-000000');
    await expect(page.getByText('Link not accepted')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible();

    await page.goto('/verify-email');
    await expect(page.getByText('This verification link is not valid.')).toBeVisible();
  });
});
