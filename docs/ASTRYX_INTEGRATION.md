# Astryx integration

Status: IMPLEMENTED and TESTED for the shell, theme, badges, search, page headers and dashboard. The remaining modules inherit the theme and the migrated shared primitives; their page-specific layouts were not rewritten.

## Compatibility

| Item | Installed | Requirement | Result |
| --- | --- | --- | --- |
| React | 19.3.1 | >= 19.0.0 peer | Compatible |
| React DOM | 19.3.1 | >= 19.0.0 peer | Compatible |
| Vite | 6.4.5 | No plugin required | Compatible |
| TypeScript | 5.7 | Typed components | Compatible |
| `@astryxdesign/core` | 0.7.13 | React 19, `@stylexjs/stylex ^0.19.0` | Installed |
| `@astryxdesign/theme-neutral` | 0.7.13 | Theme package | Installed |
| `@stylexjs/stylex` | 0.19.1 | Peer dependency | Installed |
| `@astryxdesign/cli` | 0.7.13 | Dev dependency | Installed |

Astryx is in beta. The integration pins the `latest` release, not canary. `@astryxdesign/charts` and `@astryxdesign/lab` are deliberately not installed: charts are canary-only and lab is unpublished.

## Installation

```powershell
cd frontend
npm install @astryxdesign/core@0.7.13 @astryxdesign/theme-neutral@0.7.13 @stylexjs/stylex@0.19.1
npm install -D @astryxdesign/cli@0.7.13
```

No build plugin, Babel plugin or PostCSS change was added. Astryx ships precompiled CSS and typed components.

## Stylesheets

`frontend/src/styles.css` imports the layers in this order, which is required by Astryx when Tailwind already exists:

```css
@layer reset, theme, base, astryx-base, astryx-theme, components, utilities;

@import "tailwindcss";
@import "@astryxdesign/core/reset.css";
@import "@astryxdesign/core/astryx.css";
@import "./lib/theme/secureflow.css";
```

The generated SecureFlow theme is scoped to `[data-astryx-theme="secureflow"]`, which the `Theme` provider sets.

## Theme

- Source: `frontend/src/lib/theme/secureflowTheme.ts`
- Generated: `secureflow.css`, `secureflow.js`, `secureflow.d.ts`, `secureflow.css.d.ts`, `secureflow.variants.d.ts`
- Base: `neutralTheme` from `@astryxdesign/theme-neutral/built`
- Tokens: 203 overrides, 16 component overrides
- Mode: `dark`. Light values exist in every tuple, but the legacy CSS is dark-first, so no switch is exposed.

Rebuild:

```powershell
npm run theme:build
npm run check:theme
```

`check:theme` is part of CI and fails when the committed CSS is stale.

## Provider

`frontend/src/lib/theme/AstryxProviders.tsx` wraps the router content:

```tsx
<Theme theme={secureflowTheme} mode="dark">
  <LinkProvider component={RouterLinkAdapter}>{children}</LinkProvider>
</Theme>
```

`RouterLinkAdapter` maps Astryx's `href` to React Router's `to`, so Astryx links, side navigation and buttons participate in client-side routing.

## Components used

| Astryx component | Where |
| --- | --- |
| `AppShell` | Application frame, mobile drawer, skip link, main landmark |
| `TopNav`, `TopNavHeading` | Brand, workspace name, account area |
| `SideNav`, `SideNavSection`, `SideNavItem` | Primary navigation with `aria-current` |
| `Button` | Simulation lab action in the top bar |
| `Card` | Dashboard metric cards |
| `Heading` | Page titles, semantic `h1` |
| `Text` | Page subtitles and metric values |
| `Badge` | All status, severity, priority and origin badges through the shared wrapper |
| `TextInput` | All search fields through the shared `SearchInput` |

## CLI usage

```powershell
cd frontend
npx --no-install astryx --help
npx --no-install astryx component --list
npx --no-install astryx component Table
npx --no-install astryx docs theme
npx --no-install astryx docs tokens
npx --no-install astryx template --list
```

Use the scoped package. The unscoped `astryx` package is unrelated and must not be invoked.

## Performance

Astryx adds precompiled CSS and a component runtime:

| Bundle | Before | After |
| --- | --- | --- |
| Initial JavaScript | 568 kB (155 kB gzip) | 857 kB (277 kB gzip) |
| CSS | 26.6 kB (6.9 kB gzip) | 318 kB (54.4 kB gzip) |

Route-level lazy loading reduced the initial JavaScript from the 1.09 MB it reached when all pages were eager. Page chunks load on navigation. The shell and Astryx runtime remain in the initial chunk. There is no Astryx chart package in the bundle.

## Known limitations

- Astryx is beta. A patch release can change component APIs; read the CLI docs and run `npx astryx upgrade --check` before upgrading.
- Light mode is not exposed. The theme has light values, but many legacy rules and inline styles are dark-only.
- Component migration is incremental. Tables, dialogs, tabs, pagination, charts and page-specific layouts still use the application's components and tokens.
- The generated theme names JetBrains Mono, but the repository loads no webfont. The browser falls back to the system monospace stack.

## Upgrade checklist

1. Read the release notes and `npx astryx docs migration`.
2. Update all four packages to the same version.
3. Run `npm run check:theme` and rebuild the theme.
4. Run `npm run typecheck` and `npm run build`.
5. Check the shell, badges, search fields and dashboard in a browser at a narrow width.
