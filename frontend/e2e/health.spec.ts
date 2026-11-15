import { test, expect } from '@playwright/test';

const ROUTES = [
  '/overview',
  '/trishield',
  '/monitoring',
  '/assets',
  '/websites',
  '/incidents',
  '/investigations',
  '/threat-intel',
  '/detections',
  '/phishing',
  '/vulnerabilities',
  '/network',
  '/forensics',
  '/automation',
  '/reports',
  '/simulations',
  '/settings',
];

/**
 * Shell health: every top level route must render without an uncaught error,
 * without the error boundary and without a console error. This is the guard
 * that would have caught the feature flag crash before a user saw it.
 */
for (const route of ROUTES) {
  test(`${route} renders with no uncaught error`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(`console: ${message.text()}`);
    });

    await page.goto(route);
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expect(page.getByText('This view could not be rendered')).toHaveCount(0);
    expect(errors, `runtime errors on ${route}`).toEqual([]);
  });
}
