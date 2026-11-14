# Public landing page

The landing page at `/` adapts the two maximalist reference designs to this application. It uses the existing React 19, TypeScript and CSS stack, with no new dependency.

## 1. What was taken from each design

| Reference | Applied |
| --- | --- |
| Maximalist landing | Fixed glass top bar, shader hero, gradient headline, orbit rings, dashboard preview, six feature cards, stats band, four step workflow, radar panel, CTA |
| Maximalist shader site | Shader-driven background, wavy section dividers, dither texture on cards, pointer-follow spotlight, honest status panel, light and dark support, pause for reduced motion |

## 2. What was deliberately not copied

- **Invented metrics.** The reference preview shows 1,248 events, 86 detections, 215 assets and a 98.5 percent score. None of those are real in this workspace, so the preview uses state labels instead: Streaming, Explainable, Approval gated, Hash sealed.
- **A simulated attack button on the marketing page.** The reference background reacts to fake events. On a real security product that would blur the line between demonstration and telemetry, so the landing page does not generate fake incidents. The Simulation Lab remains the place for synthetic runs, clearly labelled.
- **Canvas-distorted hero text.** The shader text mask is visually striking but inaccessible and fragile at different font sizes. The headline uses gradient text with real text underneath.
- **A 98.5 percent security score.** The radar is decorative and labelled "AUDIT / traceable by design"; it does not present a computed score.

Facts used on the page: 15 platform modules, 3 workspace roles, 5 simulation scenarios and 41 database tables. These match the repository and the schema.

## 3. Components

| File | Role |
| --- | --- |
| `frontend/src/pages/Public.tsx` | Landing markup, preview, features, workflow, radar, status, CTA |
| `frontend/src/pages/landing.css` | Scoped `.lp-*` styles, responsive rules, reduced motion |
| `frontend/src/components/PublicShader.tsx` | WebGL fluid shader with fallback |
| `frontend/src/components/ThemeSwitch.tsx` | Light, Dark and System control |
| `frontend/src/components/motion.tsx` | Scroll reveal and animated counters used on the page |

## 4. Shader behaviour

- WebGL context with a simple fragment shader: flowing fields, cursor light, procedural dither.
- Theme palettes: deep navy, cyan and violet in dark; near white, pastel blue and violet in light.
- Device pixel ratio capped at 1.35.
- Loop pauses when the tab is hidden and when the user asks for reduced motion. Reduced motion renders one static frame.
- If WebGL is unavailable, the shader fails to compile, or the context is lost, the canvas hides and a CSS gradient remains. No console error is shown.
- Theme changes rebuild the shader on the same context; the context is not force-lost.

## 5. Interaction and accessibility

- Pointer spotlight updates CSS variables directly, with no React re-render. Touch and pen are ignored for the spotlight.
- Scroll reveal uses the shared observer and the fast-scroll fallback, so no section can remain invisible.
- The mobile navigation is a disclosure with `aria-expanded` and `aria-controls`, closes on link click and Escape.
- The theme switch exposes Light, Dark and System as buttons with `aria-pressed`.
- The shader is `aria-hidden` and has no pointer events.
- The page is keyboard navigable and has no hover-only information.
- axe reports zero serious or critical violations in both themes, at desktop and mobile widths.

## 6. Responsive behaviour

- Four preview tiles become two on tablet and one workflow column stacks on mobile.
- Feature grid goes from three to two to one.
- The top bar hides the anchor links and the theme switch below 1000 and 680 pixels respectively; both are available in the mobile panel.
- No horizontal overflow at 488 pixels; verified in the browser.

## 7. Tests

| Check | Result |
| --- | --- |
| Landing axe, dark and light | 0 violations |
| Landing axe, authenticated session | 0 violations |
| Mobile menu disclosure | pass |
| Full Playwright suite | 47 passed |
| TypeScript, production build | pass |
| WebGL disabled fallback | canvas hidden, gradient visible, no page error |

## 8. Remaining limits

- The shader is a visual layer only; it does not reflect real telemetry. That is intentional.
- The preview uses sample labels, not live data; the caption says so.
- No screenshot baseline is kept for the landing page.
- The public navigation is not shared with Privacy and Terms, which keep the existing simple public header.
