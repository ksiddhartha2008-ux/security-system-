# Animation system

Status: implemented and tested with the existing React 19 and CSS stack. Framer Motion is not installed in this repository and was not added.

## 1. Architecture

| File | Purpose |
| --- | --- |
| `frontend/src/lib/motion.ts` | Reduced-motion hook, shared IntersectionObserver, scroll fallback, number formatting |
| `frontend/src/components/motion.tsx` | `ScrollReveal`, `AnimatedMetric`, `PageTransition` |
| `frontend/src/styles.css` | Motion tokens, reveal states, page, table, chart, menu and modal keyframes |
| `frontend/src/components/ui.tsx` | `Card` accepts `reveal`, `Tabs`/`TabPanel` keep the liquid pill and panel transition |
| `frontend/src/components/design.tsx` | `MetricCard` counts numeric values with `AnimatedMetric` |
| `frontend/src/components/charts.tsx` | Line, area, donut and bar entrance classes |

No animation dependency was added. The bundle grew by about 5 kB of JavaScript for the motion code.

## 2. Behaviour

### ScrollReveal

- Directions: up, down, left, right, none.
- Delay, duration, once, hover lift, custom class, `as` tag.
- Default: opacity 0, 18 px offset, 0.98 scale, then settles to a normal position.
- Uses transform and opacity only, so no layout shift.
- An element above the viewport counts as revealed. A passive scroll fallback covers a fast jump that IntersectionObserver would otherwise miss, so content can never stay invisible after the reader has passed it.

### AnimatedMetric

- Counts from the previous displayed value to the new value.
- Integer or decimal, locale aware, prefix and suffix, thousands separators, negatives.
- Rapid updates cancel the running frame and start from the current number.
- Viewport trigger, final value exposed to assistive technology, visible number hidden from it.
- Reduced motion shows the final value immediately.

### PageTransition

- Fades the route content for 240 ms on pathname change.
- Opacity only, so a fixed modal inside the page is never repositioned by a transformed ancestor.
- Reduced motion removes the animation.

### Tables

- First ten rows fade and rise with an 18 ms stagger.
- Rows from eleven onward have no animation, so a large table never creates hundreds of animations.
- Rows use opacity and translation only, keeping valid table markup.
- Incident, investigation and forensic timelines animate the first five entries with a 30 ms stagger.

### Charts and cards

- Trend lines draw once with `pathLength` and `stroke-dashoffset`.
- Areas and donut arcs fade in.
- Bar fills grow from the left.
- KPI cards rise once with a small stagger. Overview, Simulations and Automation cards reveal on scroll.

### Overlays

- Modal enters with a 6 px rise and 0.985 scale.
- Drawer keeps its slide.
- Account menu drops in with a small scale.
- Toasts keep their existing entrance and stacking.
- Tab pill glides, tab panels blur and rise (see the theme work).

## 3. Module coverage

| Module | Status | Motion applied |
| --- | --- | --- |
| Authentication | COMPLETED | Route fade, dialog entrance |
| Overview | COMPLETED | KPI count, card reveals, chart draw, table rows |
| Live monitoring | COMPLETED | Route fade, table rows. Per-event animation is intentionally absent |
| Threat intelligence | COMPLETED | Shared table rows, route fade |
| Assets | COMPLETED | Shared table rows, route fade |
| Incidents | COMPLETED | Shared table rows, route fade, tab pill |
| Investigations | COMPLETED | Route fade, shared rows |
| Detection center | COMPLETED | Tab pill, shared rows |
| Phishing scanner | PARTIALLY COMPLETED | Route fade only. Results appear from real completion, no fabricated progress |
| Vulnerabilities | COMPLETED | Shared table rows |
| SOAR | COMPLETED | Workflow card reveal, execution states unchanged |
| Forensics | COMPLETED | Shared rows, route fade |
| Network | COMPLETED | Shared rows. No per-packet animation |
| Reports | COMPLETED | KPI count, chart draw |
| Settings | COMPLETED | Tab pill, panel transition |
| Simulation lab | COMPLETED | Scenario card reveal, route fade |
| Website protection | COMPLETED | Tab pill, panel transition, route fade |

## 4. Accessibility

- `prefers-reduced-motion` is read live and disables entrance motion, counting and page fades.
- Revealed content stays in the accessibility tree; only opacity and transform change.
- Animated numbers are hidden from screen readers and a static final value is exposed.
- No animation communicates severity or state on its own.
- Keyboard focus, dialogs, tab order and skip link are unchanged.
- The axe suite covers all 16 routes in both themes and passes with zero serious or critical violations.

## 5. Performance

- One shared IntersectionObserver per threshold/root-margin pair, not one per card.
- A single passive scroll listener, active only while reveal elements are pending, throttled with requestAnimationFrame.
- Row animation capped at ten rows.
- Transform and opacity only; no width, height, top or left animation.
- No `filter` animation on large panels. The tab panel uses a 220 ms blur once.
- The particle canvas caps device pixel ratio at 1.5 and pauses when the tab is hidden.

## 6. Tests

| Check | Result |
| --- | --- |
| `npm run typecheck` | pass |
| `npm run build` | pass, 870.62 kB JS (281.38 kB gzip), 328.74 kB CSS (56.63 kB gzip) |
| `npm run test:motion --prefix frontend` | 4 passed |
| Playwright motion suite | 6 passed |
| Playwright accessibility suite | 39 passed |
| Backend suite | 123 tests, 121 passed, 2 skipped, 0 failed |

The motion suite covers fast-scroll reveal, final metric text, page transition replay, the ten-row cap, chart classes and reduced motion. A DNS resolver defect found while running these tests is fixed and covered by two regression tests in `backend/tests/website-dns.test.mjs`.

## 7. Remaining limits

- No component-level test renderer; motion is verified through Playwright and a pure formatting unit test.
- AnimatedMetric does not replay its entrance when it re-enters the viewport, by design for live KPIs. ScrollReveal can replay with `once={false}`.
- Hover lift is available on ScrollReveal but is only used where a card is interactive.
- Native browser scroll anchoring and print styles were not re-tested.
