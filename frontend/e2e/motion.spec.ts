import { test, expect } from '@playwright/test';

test.describe('motion system', () => {
  test('a fast scroll reveals every section, not only the ones that passed the viewport', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('.reveal').first()).toBeVisible();
    const container = page.locator('#astryx-app-shell-main');
    await container.evaluate((element) => { element.scrollTop = element.scrollHeight; });
    await expect(page.locator('.reveal:not(.is-visible)')).toHaveCount(0);
  });

  test('metric values settle on the same number assistive technology receives', async ({ page }) => {
    await page.goto('/reports');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('.kpi-value .sr-only').first()).toBeAttached();
    await page.waitForTimeout(1000);
    const pairs = await page.locator('.kpi-value').evaluateAll((nodes) => nodes.map((node) => ({
      visible: node.querySelector('[aria-hidden="true"]')?.textContent ?? null,
      accessible: node.querySelector('.sr-only')?.textContent ?? null,
    })));
    const animated = pairs.filter((pair) => pair.visible !== null);
    expect(animated.length).toBeGreaterThan(0);
    for (const pair of animated) expect(pair.visible).toBe(pair.accessible);
  });

  test('navigating between routes replays the page transition', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('.page-transition')).toHaveCSS('animation-name', 'page-in');
    await page.locator('a[href="/incidents"]').first().click();
    await expect(page).toHaveURL(/\/incidents/);
    await expect(page.locator('.page-transition')).toHaveCSS('animation-name', 'page-in');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  });

  test('table rows animate only the first ten rows', async ({ page }) => {
    await page.goto('/assets');
    await page.waitForLoadState('networkidle');
    const rows = page.locator('.data tbody tr');
    await expect(rows.first()).toBeVisible();
    const animations = await rows.evaluateAll((nodes) => nodes.map((node) => getComputedStyle(node).animationName));
    expect(animations[0]).toBe('row-in');
    if (animations.length > 10) expect(animations[10]).toBe('none');
  });

  test('chart paths and replayable reveals are wired to the motion tokens', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('.chart-line').first()).toHaveCSS('animation-name', 'chart-draw');
    await expect(page.locator('.chart-area').first()).toHaveCSS('animation-name', 'chart-fade');
  });
});

test.describe('signal flow motion', () => {
  test('page sections stagger in on every route', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    const sections = page.locator('.page-transition > *');
    await expect(sections.first()).toHaveCSS('animation-name', 'section-in');
    await expect(sections.nth(1)).toHaveCSS('animation-delay', '0.055s');
  });

  test('the ambient field drifts and stays out of the accessibility tree', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    const layer = page.locator('.fluid-layer');
    await expect(layer).toHaveAttribute('aria-hidden', 'true');
    const animation = await layer.evaluate((node) => getComputedStyle(node, '::before').animationName);
    expect(animation).toBe('ambient-drift');
  });

  test('the scroll progress follows the main scroll container', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    const bar = page.locator('.scroll-progress');
    await expect(bar).toHaveAttribute('aria-hidden', 'true');
    await expect.poll(async () => Number(await bar.evaluate((node) => getComputedStyle(node).getPropertyValue('--scroll-progress') || '0'))).toBeLessThan(0.01);
    await page.locator('#astryx-app-shell-main').evaluate((element) => { element.scrollTop = element.scrollHeight * 0.5; });
    await expect.poll(async () => Number(await bar.evaluate((node) => getComputedStyle(node).getPropertyValue('--scroll-progress') || '0'))).toBeGreaterThan(0.2);
    await expect(page.locator('.content-shell')).toHaveAttribute('data-scrolled', 'true');
  });

  test('a card sheen follows the pointer without a re-render', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    const card = page.locator('.page .card').first();
    await card.hover({ position: { x: 40, y: 30 } });
    await expect.poll(async () => card.evaluate((node) => (node as HTMLElement).style.getPropertyValue('--pointer-x'))).not.toBe('');
  });
});

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' });

  test('content is visible immediately and entrance animation is suppressed', async ({ page }) => {
    await page.goto('/overview');
    await page.waitForLoadState('networkidle');
    const reveals = page.locator('.reveal');
    await expect(reveals.first()).toBeVisible();
    await expect(page.locator('.reveal:not(.is-visible)')).toHaveCount(0);
    const duration = await reveals.first().evaluate((node) => getComputedStyle(node).transitionDuration);
    expect(Number.parseFloat(duration)).toBeLessThan(0.01);
    await expect(page.locator('.page-transition')).toHaveCSS('animation-duration', /0\.000001s|1e-06s/);
    await expect(page.locator('.page-transition > *').first()).toHaveCSS('animation-name', 'none');
    const ambient = await page.locator('.fluid-layer').evaluate((node) => getComputedStyle(node, '::before').animationName);
    expect(ambient).toBe('none');
  });
});
