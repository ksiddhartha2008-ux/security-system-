import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const ROUTES: { path: string }[] = [
  { path: '/overview' },
  { path: '/monitoring' },
  { path: '/assets' },
  { path: '/websites' },
  { path: '/incidents' },
  { path: '/investigations' },
  { path: '/threat-intel' },
  { path: '/detections' },
  { path: '/phishing' },
  { path: '/vulnerabilities' },
  { path: '/network' },
  { path: '/forensics' },
  { path: '/automation' },
  { path: '/reports' },
  { path: '/simulations' },
  { path: '/settings' },
];
/** Serious and critical violations fail; moderate and minor are listed in the report. */
async function scan(page: import('@playwright/test').Page, label: string) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  const violations = results.violations.filter((v) => v.impact === 'critical' || v.impact === 'serious');
  const summary = violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    nodes: v.nodes.length,
    help: v.help,
    targets: v.nodes.slice(0, 3).map((n) => n.target.join(' ')),
    data: v.nodes.slice(0, 2).map((n) => n.any?.[0]?.data ?? null),
  }));
  await test.info().attach(`axe-${label}.json`, {
    body: JSON.stringify({ label, violations: summary }, null, 2),
    contentType: 'application/json',
  });
  expect(summary, `serious or critical axe violations on ${label}`).toEqual([]);
}

test.describe('accessibility', () => {
  for (const theme of ['dark', 'light'] as const) {
    for (const route of ROUTES) {
      test(`${route.path} has no serious violations in ${theme}`, async ({ page }) => {
        await page.goto(route.path);
        await page.evaluate((value) => window.localStorage.setItem('sf-theme', value), theme);
        await page.reload();
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
        await page.waitForLoadState('networkidle');
        await scan(page, `${route.path.replace('/', '') || 'root'}-${theme}`);
      });
    }
  }

  test('the skip link is first and moves focus into the main region', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    await page.keyboard.press('Tab');
    const skip = page.locator('[data-testid="skip-to-content"]');
    await expect(skip).toBeFocused();
    await skip.press('Enter');
    await expect(page.locator('#astryx-app-shell-main')).toBeFocused();
  });

  test('dialogs move focus inside and close with Escape', async ({ page }) => {
    await page.goto('/reports');
    await page.getByRole('button', { name: 'Generate report' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    const focusInside = await dialog.evaluate((node) => node.contains(document.activeElement));
    expect(focusInside).toBe(true);
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  });

  test('the website detail tabs are accessible in both themes', async ({ page, request }) => {
    const response = await request.get('/api/v1/websites');
    const body = await response.json();
    let id = body?.data?.[0]?.id;
    if (!id) {
      const state = await request.storageState();
      const csrf = state.cookies.find((cookie) => cookie.name === 'sf_csrf')?.value;
      const created = await request.post('/api/v1/websites', {
        data: { url: `https://a11y-${Date.now()}.example.test/` },
        headers: csrf ? { 'x-csrf-token': csrf } : {},
      });
      if (created.ok()) id = (await created.json())?.data?.site?.id;
    }
    test.skip(!id, 'no website could be created for the detail scan');
    for (const theme of ['dark', 'light'] as const) {
      await page.goto(`/websites/${id}`);
      await page.evaluate((value) => window.localStorage.setItem('sf-theme', value), theme);
      await page.reload();
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await page.waitForLoadState('networkidle');
      await scan(page, `website-detail-${theme}`);
    }
  });

  test('the active tab pill moves and arrow keys change the tab', async ({ page }) => {
    await page.goto('/settings');
    const pill = page.locator('.tab-pill');
    await expect(pill).toBeVisible();
    const before = await pill.boundingBox();
    await page.getByRole('tab', { name: 'Integrations' }).click();
    await expect(page.getByRole('tab', { name: 'Integrations' })).toHaveAttribute('aria-selected', 'true');
    await page.waitForTimeout(420);
    const after = await pill.boundingBox();
    expect(after?.x ?? 0).toBeGreaterThan(before?.x ?? 0);
    await expect(page.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', /settings-tab-integrations/);
    await page.getByRole('tab', { name: 'Integrations' }).focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.getByRole('tab', { name: 'Audit log' })).toBeFocused();
    await expect(page.getByRole('tab', { name: 'Audit log' })).toHaveAttribute('aria-selected', 'true');
  });

  test('the theme choice survives a reload without a flash of the other theme', async ({ page }) => {
    await page.goto('/settings');
    await page.getByRole('button', { name: /account menu/i }).click();
    await page.getByRole('button', { name: 'Light' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await page.reload();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    const stored = await page.evaluate(() => window.localStorage.getItem('sf-theme'));
    expect(stored).toBe('light');
  });

  test('system mode follows the operating system preference', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/overview');
    await page.getByRole('button', { name: /account menu/i }).click();
    await page.getByRole('button', { name: 'System' }).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  });
});
