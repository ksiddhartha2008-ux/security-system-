# Accessibility

## What the interface provides

- **Landmarks.** `AppShell` renders the skip link, the banner slot, one top navigation landmark, one side navigation landmark and one main landmark. Pages never add a second `<main>`.
- **Skip link.** First focusable element, visible on focus, moves focus to the content region.
- **Current page.** `SideNavItem` sets `aria-current="page"` for the active destination.
- **Mobile navigation.** `AppShell` turns the side navigation into a modal drawer, traps focus, closes on Escape and returns focus to the toggle.
- **Controls.** Buttons have visible text or an accessible name. Astryx `Button` keeps focus while loading with `aria-busy` instead of dropping focus through `disabled`.
- **Inputs.** `SearchInput` uses Astryx `TextInput` with a real, visually hidden label plus `type="search"` and a clear control. Form fields use `Field` with a `<label for>`.
- **Status language.** Severity, priority, verification and connection states always include a word. The Astryx `Badge` carries the text; colour is secondary.
- **Tables.** Data tables use `<thead>`, `<th>` header cells and a caption or heading in the surrounding card.
- **Dialogs.** The application `Modal`, `Drawer` and `ConfirmDialog` trap Tab, close on Escape, restore focus and label the dialog with `aria-labelledby`.
- **Live regions.** Toasts use `aria-live="polite"`. Form errors use `role="alert"`. The loading skeleton sets `aria-busy`.
- **Focus ring.** The theme sets `--focus-outline-color` to the accent (`#4D9DFF` in dark mode), width 2 px and offset 3 px. Astryx components use the shared focus tokens.
- **Reduced motion.** The stylesheet includes a `prefers-reduced-motion` rule that collapses animation and transition duration.

## Checks performed

A DOM audit ran in the running application at a 488 px viewport after the migration. It checked visible buttons for an accessible name, inputs for a label, images for `alt`, tables for header cells, duplicate ids and heading-level skips.

| Route | Buttons | Missing names | Inputs | Unlabelled | Tables without `th` | Heading skips | Horizontal scroll |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `/overview` | 2 | 0 | 0 | 0 | 0 | 0 | none |
| `/monitoring` | 10 | 0 | 3 | 0 | 0 | 0 | none |
| `/incidents` | 11 | 0 | 2 | 0 | 0 | 0 | none |
| `/websites` | 4 | 0 | 2 | 0 | 0 | 0 | none |
| `/assets` | 9 | 0 | 2 | 0 | 0 | 0 | none |
| `/settings` | 9 | 0 | 5 | 0 | 0 | 0 | none |
| `/demo-data` | 14 | 0 | 0 | 0 | 0 | 0 | none |
| `/reports` | 13 | 0 | 0 | 0 | 0 | 0 after the report-types heading fix | none |

A route smoke run visited all 18 authenticated routes. Every route rendered its expected `h1`, produced no `role="alert"` error box, and loaded its lazy chunk.

Keyboard checks performed manually in the browser:

- Tab from the top of the page reaches the skip link, then the product heading, navigation and page actions.
- The mobile navigation drawer opens from the menu button, contains the grouped links and closes with Escape.
- The account menu opens with Enter, closes with Escape and returns focus to its trigger.
- Dialog focus moves to the first control and returns to the trigger on close.

## Gaps

- No automated engine such as axe-core was run. The repository has no browser test runner, and adding one was outside the UI integration.
- Light mode is not exposed, so light-mode contrast ratios were not measured. Dark values were chosen from the supplied SecureFlow theme and meet the intended contrast, but no tool verified every pair.
- Screen reader output was not tested with NVDA, JAWS or VoiceOver.
- 360 px was not tested; the layout was checked at 488 px and uses the existing 620 px and 900 px breakpoints.
- The report type buttons previously contained `h3` elements, which produced a heading skip and invalid button content. They now use a section `h2` and plain text inside the button.

## Rules for new work

1. Read the Astryx component documentation before composing a new control.
2. Give every icon-only control a name, and every input a label.
3. Do not use a clickable `div` when a button or link is correct.
4. Keep one `h1` per page. Section cards use `h2`; do not skip a level.
5. Test the page at 488 px with a keyboard before calling it done.
