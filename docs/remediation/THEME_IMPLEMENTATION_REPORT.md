# Theme implementation report

## Status

| Item | Status |
| --- | --- |
| Light theme tokens | IMPLEMENTED, TESTED |
| Dark theme tokens | IMPLEMENTED, TESTED |
| System theme | IMPLEMENTED, TESTED |
| Preference persistence | IMPLEMENTED, TESTED |
| No flash before first paint | IMPLEMENTED, reviewed |
| Charts readable in both themes | IMPLEMENTED, TESTED by axe |
| All 16 authenticated routes | TESTED in both themes |
| Screenshot based visual diff | NOT IMPLEMENTED |

## 1. Before

`frontend/src/styles.css` defined dark values in `@theme` and `:root`, with `color-scheme: dark`. Astryx was mounted with `mode="dark"` in `frontend/src/lib/theme/AstryxProviders.tsx`. Colours that were not tokenised were hardcoded: 65 in `styles.css` and 96 in TSX, including chart strokes, text greys and dark panel fills.

The Astryx theme source already contains `[light, dark]` tuples for every token, so the design system side was ready; the application CSS and the provider mode were not.

## 2. Token model

`frontend/src/styles.css` now has:

- `@theme` values for Tailwind utilities (dark defaults)
- `:root` with the full token set including semantic colours (`--color-ink-soft`, `--color-danger-text`, `--color-chart-grid`, and so on)
- `html[data-theme="light"]` overriding the same variables, including `color-scheme: light`

Because every module reads the variables, light mode is one override block. A component that hardcodes a colour would stand out in review; the accessibility scan also catches unreadable results.

## 3. Runtime

`frontend/src/lib/theme/ThemeMode.tsx`:

- Modes: `light`, `dark`, `system`.
- Stored in `localStorage` under `sf-theme`.
- `system` listens to `prefers-color-scheme` and updates without a reload.
- Sets `document.documentElement.dataset.theme`, `color-scheme`, and the `theme-color` meta value.

`frontend/public/theme-init.js` runs in the document head before the stylesheet paints and applies the stored choice. It is an external same-origin script, so the strict CSP (`script-src 'self'`) does not need an inline exception.

`AstryxProviders` passes the resolved theme to `<Theme mode={resolved}>`, so Astryx components and the application CSS always agree.

## 4. Control

The account menu has an Appearance group with three buttons: Light, Dark, System. Each has `aria-pressed`, visible text and a 12 px icon. The control is inside the menu, so it is reachable from every authenticated page. A copy in Settings was not added to avoid two sources of truth.

## 5. Charts

`frontend/src/components/charts.tsx` now applies series colours through CSS properties (`style={{ stroke }}`, `style={{ stopColor }}`) rather than presentation attributes, so `var(--color-...)` resolves correctly. Grid, axis, point and gauge track colours use chart specific tokens that flip with the theme.

## 6. Verification

- Playwright scans all 16 routes in both themes with axe: 0 violations.
- Computed styles on the overview, incidents, detections, reports, settings and monitoring routes were checked: light body `rgb(244,246,250)`, panel `rgb(255,255,255)`, text `rgb(21,34,56)`; dark body `rgb(10,14,21)`, text `rgb(233,239,249)`.
- The persistence test sets Light, reloads, and asserts `data-theme="light"` and the stored value.
- The system test emulates a dark OS, selects System, asserts dark, then emulates light and asserts a live switch.

## 7. Known limits

- No visual regression baseline; a colour change is caught by contrast and review, not by pixel diff.
- The public marketing pages were tokenised too, but the axe route list covers authenticated pages. The login page is exercised by the setup test and the earlier browser pass.
- Print styles are unchanged and were not reviewed.
- Forced colours mode is handled by the tokens but not tested.

## 8. Files changed

- `frontend/src/styles.css`
- `frontend/src/lib/theme/ThemeMode.tsx` (new)
- `frontend/src/lib/theme/AstryxProviders.tsx`
- `frontend/src/components/layout.tsx`
- `frontend/src/components/charts.tsx`
- `frontend/src/App.tsx`
- `frontend/index.html`
- `frontend/public/theme-init.js` (new)
- page modules replaced hardcoded colours with tokens
