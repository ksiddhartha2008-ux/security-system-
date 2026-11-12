# SecureFlow design system

The interface is a security operations console: dense, calm, readable and explicit about the source of every number. Astryx supplies the primitives and the token layer; SecureFlow owns the domain components.

## Principles

1. **Information before decoration.** No gradients, glow effects or decorative animation. Motion is limited to loading and focus feedback.
2. **Text carries meaning.** Severity and status always include a readable label. Colour is a second signal, never the only one.
3. **One hierarchy.** Page title, section title, row, supporting text. Components do not invent their own type scale.
4. **Dark first.** Analysts work in a dark room against a dark surface. Light values exist in the theme but are not exposed yet.
5. **Every number has a source.** Counts are SQL aggregates from the API. Simulated values are labelled SIMULATED or described as synthetic.
6. **Reuse before addition.** `components/ui.tsx` and `components/design.tsx` are the shared layer. A new primitive needs a reason.

## Tokens

The SecureFlow theme extends Astryx neutral. Dark values are the active mode.

| Semantic role | Token | Dark value |
| --- | --- | --- |
| Application background | `--color-background-body` | `#0A0E15` |
| Main surface | `--color-background-surface` | `#0E141F` |
| Card surface | `--color-background-card` | `#131B2A` |
| Muted surface | `--color-background-muted` | `#0B111B` |
| Popover | `--color-background-popover` | `#1A2334` |
| Primary text | `--color-text-primary` | `#E9EFF9` |
| Secondary text | `--color-text-secondary` | `#9DACCA` |
| Disabled text | `--color-text-disabled` | `#5A6A87` |
| Border | `--color-border` | `#253149` |
| Emphasised border | `--color-border-emphasized` | `#384664` |
| Accent | `--color-accent` | `#4D9DFF` |
| Critical | `--color-error` / red family | `#FF6B6E` |
| High | `--color-warning` / orange family | `#FFA35C` |
| Medium | yellow family | `#F2C744` |
| Low | blue family | `#7CB8FF` |
| Success | `--color-success` | `#3FCE8E` |
| Information | `--color-info` | `#61B3FF` |
| Focus ring | `--focus-outline-color` | `#4D9DFF`, 2px, 3px offset |

Radius: `base: 5`, multiplier `1`. Typography: base 14, ratio 1.2, Segoe UI with system fallbacks. Code uses the system monospace stack.

## Severity mapping

| Severity | Astryx Badge variant | Also shown as |
| --- | --- | --- |
| critical | `red` | text label `critical` |
| high | `orange` | text label `high` |
| medium | `yellow` | text label `medium` |
| low | `blue` | text label `low` |
| info | `blue` | text label `info` |
| healthy / connected | `green` | text label |
| neutral / unknown | `gray` | text label |

The shared `Badge` wrapper in `components/ui.tsx` performs this mapping. Pages do not pass raw colours.

## Components

### Astryx primitives

`AppShell`, `TopNav`, `TopNavHeading`, `SideNav`, `SideNavSection`, `SideNavItem`, `Button`, `Card`, `Heading`, `Text`, `Badge`, `TextInput`.

### Application components

| Component | File | Why it is application owned |
| --- | --- | --- |
| `PageHeader` | `components/layout.tsx` | Wraps Astryx `Heading` and `Text` with the page action layout |
| `MetricCard` | `components/design.tsx` | Astryx `Card` plus the KPI label, value and spark layout |
| `Badge`, `SeverityBadge`, `StatusBadge`, `RiskBadge`, `OriginBadge` | `components/ui.tsx` | Domain mapping from severity and status to text and variant |
| `SearchInput` | `components/ui.tsx` | Astryx `TextInput` with the application search behaviour |
| `Card` | `components/ui.tsx` | Section container with header, actions and footer slots |
| `Modal`, `Drawer`, `ConfirmDialog` | `components/ui.tsx` | Focus trap, escape handling, destructive confirmation |
| `Tabs`, `Pagination`, `EmptyState`, `ErrorState`, `TableSkeleton` | `components/ui.tsx` | Stable page behaviour and loading/error language |
| `TrendChart`, `Donut`, `Sparkline`, `RankBars`, `RiskGauge` | `components/charts.tsx` | Hand-built SVG over real API series; no chart dependency |

## Layout rules

- Page content is wrapped in `.page`, max width 1500 px, with a 24 px gutter and 56 px bottom space.
- The shell owns navigation, the skip link and the main landmark. Pages never add a second `<main>`.
- Card padding is consistent (16 px). Cards are for discrete items and metric tiles, not every section.
- Tables keep `scope`-less `<th>` header cells inside `<thead>`; the first column is the row label.
- Forms use a visible label. A hidden label is allowed only for a search field with a magnifying glass and a placeholder.
- At 620 px the sidebar becomes a drawer, page padding drops to 18/14 px and multi-column grids collapse.

## Copy rules

- Plain and specific. Say “Failed sign-in”, not “Authentication anomaly detected by AI”.
- No invented counts, customers, uptime or accuracy claims.
- Synthetic data says so: demo records use the `DEMO` origin, simulation runs use `SIMULATED`, test websites show `test domain`.
- No em dashes in interface copy.

## Adding a component

1. Check `components/ui.tsx` and `components/design.tsx` first.
2. Read the Astryx component documentation with the CLI.
3. Prefer composition over a new wrapper.
4. Add the accessible name, focus state and empty/error state at the same time.
5. Use tokens, not new hex values. If a token is missing, add it to `secureflowTheme.ts` and rebuild.
