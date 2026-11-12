# UI component mapping

## Shared primitives

| SecureFlow component | Implementation | Astryx component | Notes |
| --- | --- | --- | --- |
| `Badge`, `SeverityBadge`, `StatusBadge`, `RiskBadge`, `OriginBadge` | `components/ui.tsx` | `Badge` | Tone-to-variant mapping, always a text label |
| `SearchInput` | `components/ui.tsx` | `TextInput` | Hidden but real label, search type, clear control |
| `PageHeader` | `components/layout.tsx` | `Heading`, `Text` | Semantic `h1` plus supporting copy |
| `MetricCard` | `components/design.tsx` | `Card`, `Text` | Dashboard KPI tile |
| Application shell | `components/layout.tsx` | `AppShell`, `TopNav`, `TopNavHeading`, `SideNav`, `SideNavSection`, `SideNavItem`, `Button` | Navigation, branding, account area, simulation action |
| `Card` | `components/ui.tsx` | None | Section container with title, actions and footer slots |
| `Button` | `components/ui.tsx` | None | Loading, icon, variant and size API used across every page |
| `Modal`, `Drawer`, `ConfirmDialog` | `components/ui.tsx` | None | Focus trap, Escape, destructive confirmation |
| `Tabs`, `Pagination` | `components/ui.tsx` | None | Existing page behaviour and URL-free state |
| `EmptyState`, `ErrorState`, `TableSkeleton` | `components/ui.tsx` | None | Consistent loading, empty and error language |
| `TrendChart`, `Donut`, `Sparkline`, `RankBars`, `RiskGauge` | `components/charts.tsx` | None | SVG over API series, no chart dependency |

## Module mapping

| Module | Astryx in use | Application components | Migration state |
| --- | --- | --- | --- |
| Authentication | `Badge` | Demo profile picker, role segmented control, standard credential form | Redesigned to match the reference demo access screen while keeping real API sign-in |
| Security overview | `Card`, `Text`, `Badge`, `Heading` | Charts, tables, metric wrapper | Shell, header, badges and metric tiles migrated |
| Live monitoring | `Badge`, `TextInput`, `Heading` | Event table, detail drawer, filters | Shared primitives migrated |
| Threat intelligence | `Badge`, `TextInput`, `Heading`, metric cards | Indicator table, lookup panel, filters | Shared primitives and real KPI strip migrated |
| Asset management | `Badge`, `TextInput`, `Heading` | Asset table, register dialog | Shared primitives migrated |
| Incident management | `Badge`, `TextInput`, `Heading`, metric cards | Incident list, lifecycle control, timeline | Shared primitives and KPI strip migrated |
| Threat investigation | `Badge`, `Heading` | Notes, findings, evidence cards | Shared primitives migrated |
| Detection centre | `Badge`, `TextInput`, `Heading`, metric cards | Detection table, rule factors, feedback | Shared primitives and KPI strip migrated |
| Phishing scanner | `Badge`, `Heading` | URL form, result panel, history | Shared primitives migrated |
| Vulnerability management | `Badge`, `TextInput`, `Heading` | Register table, remediation control | Shared primitives migrated |
| SOAR | `Badge`, `Heading` | Workflow cards, approval dialog, execution log | Shared primitives migrated; action status remains SIMULATED |
| Digital forensics | `Badge`, `Heading` | Evidence table, hash panel, custody timeline | Shared primitives migrated |
| Network monitoring | `Badge`, `TextInput`, `Heading` | Flow table, traffic charts | Shared primitives migrated |
| Reports and analytics | `Badge`, `Heading`, metric cards | Report cards, generated table, posture snapshot | Shared primitives, posture snapshot and report-type heading migrated |
| Settings and administration | `Badge`, `Heading` | Forms, member table, audit table, integration cards | Shared primitives migrated |
| Website protection | `Badge`, `Heading` | Wizard, verification record, key dialog, tabs | Shared primitives migrated |

## Deliberately not forced

- **Tables.** The application table styles carry numeric alignment, truncation, severity cells and pagination that Astryx Table would need reimplemented. Shared Badges inside the cells give the design-system look without a risky table rewrite.
- **Dialogs.** The application dialogs already trap focus, restore focus and support destructive confirmations. Copying Astryx Dialog would duplicate behaviour and risk regressions.
- **Charts.** Astryx chart packages are canary or unpublished. The existing SVG charts read real API series and stay.
- **Tabs and pagination.** Both are small, accessible and already used by every module; they were not replaced for consistency points alone.
- **Forms.** Astryx `TextInput` is used for search. Form fields keep the application `Field`, `select` and `textarea` styling until a module-by-module form migration is scheduled.
