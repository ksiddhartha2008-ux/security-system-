# Accessibility report

## Status

| Item | Status |
| --- | --- |
| Automated axe scan, 16 routes, dark and light | IMPLEMENTED, TESTED, 0 violations |
| Keyboard skip link | TESTED |
| Dialog focus and Escape | TESTED |
| Form label and error association | IMPLEMENTED, TESTED in the earlier health pass |
| Theme persistence and system mode | TESTED |
| Reduced motion | IMPLEMENTED in CSS (`prefers-reduced-motion`), not manually profiled |
| Screen reader walkthrough | NOT VERIFIED |
| Lighthouse audit | NOT RUN |

## 1. Tooling

- Playwright 1.65 with Chromium.
- `@axe-core/playwright` 4.14 running axe-core with tags `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`.
- Tests start their own API on port 4100 with a dedicated database, sign in once, and reuse the session.

Files:

- `frontend/playwright.config.ts`
- `frontend/e2e/auth.setup.ts`
- `frontend/e2e/a11y.spec.ts`

## 2. Coverage

Sixteen authenticated routes, each scanned in dark and light: overview, monitoring, assets, websites, incidents, investigations, threat intel, detections, phishing, vulnerabilities, network, forensics, automation, reports, simulations, settings.

Plus five interaction tests:

1. The skip link is the first focusable element and moves focus to the main region.
2. A dialog moves focus inside and closes with Escape.
3. A theme choice survives a reload.
4. System mode follows the operating system preference.
5. Light and dark produce no serious contrast failure.

Total: 37 tests. Latest run: 37 passed, 0 failed, in 1.2 minutes.

## 3. Violations found and fixed

First run:

| Rule | Impact | Nodes | Cause | Fix |
| --- | --- | --- | --- | --- |
| `color-contrast` | serious | 128 | light theme `--color-faint` was 4.29 to 4.4:1 on card surfaces | darkened to `#5b6a7e`, dark theme to `#74889c` |
| `label-content-name-mismatch` | serious | 16 | the account button had an `aria-label` that did not contain its visible text | removed the label and added a visually hidden "account menu" suffix so the computed name includes the visible name and role |

After the fixes, a full scan of all 16 routes in both themes reports **0 violations at any impact level**, not only serious.

## 4. Keyboard and focus

- Skip link: first Tab focuses it, Enter moves focus to `#astryx-app-shell-main`.
- Dialog: focus moves inside on open, Escape closes, focus returns to the trigger.
- Navigation: sidebar links are in DOM order, the account menu is a labelled menu button with `aria-expanded`.
- Tables: sortable or filterable controls are real form controls with labels.
- Charts: each SVG has `role="img"` and an `aria-label` that summarises the series totals.

## 5. Forms

- Every field has a `<label for>` association.
- Validation messages are linked with `aria-describedby` and the control is marked `aria-invalid` (implemented in `frontend/src/components/ui.tsx` during the earlier health pass).
- Error text is announced with `role="alert"`.

## 6. Contrast

Both themes were checked by axe with the contrast rule enabled. The test does not disable any rule. The tokens are in `frontend/src/styles.css`; the light block overrides the same variables, so a component cannot drift to a dark only colour without failing the scan.

## 7. Responsive behaviour

The browser pass in the health report covered 488 px width. The accessibility suite runs at 1280 px. A dedicated small viewport accessibility run is NOT IMPLEMENTED; the same components are used at both sizes, but this is not proof.

## 8. CI

The `accessibility` job in `.github/workflows/ci.yml` installs Chromium, builds the client, runs the 37 tests and uploads `frontend/test-results` as an artifact. A failure blocks the workflow.

## 9. Remaining work

- Manual screen reader pass with NVDA and VoiceOver.
- Lighthouse run for performance and best practice scores.
- Small viewport accessibility scan.
- High contrast and forced colours mode review.

These are listed so the automated result is not overstated: automated axe coverage is strong, but it cannot replace a manual assistive technology pass.
