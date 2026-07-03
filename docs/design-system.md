# MXID Frontend Design System

> Single source of truth for the console/portal UI. Read this before building any
> page — follow it and you get a consistent, dark-mode-ready, commercial-grade UI
> without re-inventing layout or color.

**Aesthetic**: floating rounded panels, generous whitespace, soft shadows, dark
sidebar + light content, semantic status pills. Blue/white enterprise look
(benchmark: Isora / Okta). No neon, no heavy gradients, no cyberpunk.

**Stack**: React 19 + Vite + TypeScript + Tailwind **v4** + framer-motion +
zustand + axios + recharts + lucide-react. Shared primitives in
`@mxid/shared/ui`, consumed by both `apps/console` and `apps/portal`.

---

## 0. Golden rules (violating = rework)

1. **No hardcoded color values.** Use semantic token utilities (`bg-surface`,
   `text-ink`, `text-muted`, `border-border`, `bg-primary`, `text-danger`…),
   never `bg-white` / `text-gray-500` / hex. Tokens adapt to light/dark for free.
2. **Import UI from `@mxid/shared/ui`.** Don't hand-roll buttons/tables/modals.
   Missing a component? Build it into the shared kit, then use it.
3. **List/detail/settings pages follow the templates in §5.** Don't invent a
   per-page layout.
4. **Every write gives toast feedback** (`toast.success` / `toast.error`), never
   silent. One notification per error (toast OR inline, not both).
5. **Three states handled**: loading / empty / error. Empty → `EmptyState` /
   `DataTable`'s built-in empty.
6. **Destructive actions get a second confirm** (`ConfirmDialog`).
7. **Zero hardcoded copy** — everything through i18n (`common.*` + module ns).
8. **Data access via the api layer** (`@mxid/shared` `*Api` + axios wrapper),
   never a bare axios/fetch in a component.

---

## 1. Design tokens

Defined in each app's `src/index.css`. Colors are RGB triplets in `:root` /
`.dark`; `@theme` maps them to Tailwind utilities. `.dark` swaps the same
variable names, so one class works in both modes.

### Colors (semantic, not decorative)
| Role | token utility | notes |
|---|---|---|
| Canvas | `bg-bg` | app background |
| Card / surface | `bg-surface` | cards, panels |
| Sub-fill / table head | `bg-surface-muted` | headers, hover fills |
| Hairline border | `border-border` | dividers |
| Strong border | `border-border-strong` | card edges (visible in dark) |
| Brand | `bg-primary` `text-primary` (+`primary-hover`) | actions, links |
| Semantic | `success` `warning` `danger` `info` | status only, tint via `/10` |
| Text | `text-ink` (primary) `text-muted` (secondary) `text-faint` (tertiary) | |

Tints: `bg-success/10 text-success` for pills. Opacity modifier works because v4
handles it via `color-mix`.

### Radius / shadow
- Radius: `rounded-panel`(20) app panel · `rounded-card`(16) cards ·
  `rounded-control`(10) buttons/inputs · `rounded-full` pills.
- Shadow: `shadow-card` (rest) · `shadow-hover` (hover) · `shadow-float` (overlay).

### Dark mode
Class strategy (`.dark` on `<html>`), **not** `prefers-color-scheme`.
`useTheme` (zustand) persists to `localStorage['mxid.theme']`; a FOUC script in
`index.html` applies it before paint. Toggle via `<ThemeToggle />` (in Header).

> **Legacy compat shim** (`.dark main …` in `index.css`): remaps hardcoded
> `bg-white`/`text-gray-*`/pills to tokens for not-yet-migrated pages. As you
> migrate a page to tokens, its entries become dead — the shim is temporary.

---

## 2. Component kit (`@mxid/shared/ui`)

| Component | Purpose / key props |
|---|---|
| `Button` | `variant: primary\|secondary\|danger\|warning\|success\|ghost`, `size`, `loading`, `icon` |
| `Input` / `Textarea` / `Select` | styled native controls (`INPUT_CLASS`) |
| `Field` / `FormField` | label + control + hint/error (required star, inline error) |
| `Modal` | centered dialog (`open,title,onClose,size`) |
| `Drawer` | right-slide panel (`open,onClose,title,width,footer`) |
| `ConfirmDialog` | destructive second-confirm (`danger,onConfirm,onCancel`) |
| `Card` / `CardHeader` | surface container + header |
| `PageHeader` | title + description + `extra`/`actions` |
| `StatCard` | KPI tile: tinted icon chip + big `tabular-nums` value (`tone`) |
| `ChartCard` | chart frame (put recharts as children) |
| `DataTable<T>` | `columns`(key/title/align/render)/`rows`/`rowKey`/`loading`/`onRowClick`/`selectable` |
| `Pagination` | `page,pageSize,total,onChange` (tabular-nums) |
| `FilterBar` / `SearchInput` | filter row + search box |
| `Tabs` | pill segmented control |
| `Switch` | boolean toggle |
| `RangePicker` | date range + presets (`lastNDays`) |
| `StatusTag` | status pill by `tone`; pair with tone helpers |
| `Tag` | decorative pill (`variant`) |
| `ThemeToggle` | light/dark switch |

### Tone helpers (`tone.tsx`) — derive color from data, never scatter ternaries
- `statusTone(status)` → tone for `active/pending/failed/…`
- `severityTone(level)` → tone for `critical/high/medium/low`
- `httpTone(code)` → 2xx success / 3xx info / 4xx warn / 5xx danger

```tsx
<StatusTag tone={statusTone(row.status)}>{row.status}</StatusTag>
```

### Component rules
- Pure presentation, data comes via props. No fetching inside display components.
- Every clickable row/item has a hover state.
- Icons: lucide-react, 16–20px.
- Variants: hand-written `Record<Variant,string>` + `cn()` (clsx+tailwind-merge).
  No `cva`, no heavy libs.

---

## 3. Data layer (axios + zustand, **no TanStack Query**)

- One api module per resource in `@mxid/shared/api` exporting `<name>Api`
  (`get/post/put/del`), responses via the shared axios wrapper (`{code,message,data}`).
- Component state: `useState`/`useEffect` load, or a per-resource zustand store
  with `{ data, loading, error, fetch, mutate }`. Handle all three states.
- List filters/pagination sync to the URL with `useUrlState` (shareable,
  back/forward-safe):

```ts
const [q, setQ] = useUrlState({ page: 1, keyword: '', status: '' })
setQ({ keyword: 'bob', page: 1 })   // → ?keyword=bob
```

---

## 4. Layout & interaction

- **Shell**: floating panel — `p-3` → `rounded-panel bg-surface shadow-card` →
  `[Sidebar w-60 (dark) | Header h-16 + <main> content]`. Content lives in
  `<main>` (dark shim + page motion apply there).
- **Page enter**: framer-motion fade+rise (`pageMotion`, y:8→0, 0.25s).
- **Create/edit**: `Drawer` (many fields) or `Modal` (few) → save → toast → close → refresh.
- **Motion**: restrained, 0.18–0.25s — Modal scale / Drawer slide / page fade /
  card `hover:-translate-y-0.5`. No looping animation.
- **Responsive**: mobile-first, one main breakpoint `lg:`.

---

## 5. Page templates

### 5.1 List page (users / apps / audit / …) — see `pages/users` for the reference
```
PageHeader(title, description, actions=<Button>New</Button>)
FilterBar( SearchInput, Select… )
Card{ DataTable(columns, rows, rowKey, loading, onRowClick) + Pagination }
Drawer/Modal (create/edit)  +  ConfirmDialog (delete)
```

### 5.2 Settings / form page
`PageHeader` → one `Card` per section (`CardHeader` = section title) → `FormField`
column → save `Button`. Load current values, `mutate` on save.

### 5.3 Master–detail (RBAC)
Left `Card` (list, selected highlighted) + right `Card` (detail/permissions grid).

### 5.4 Tabbed page (reports)
`PageHeader(extra=RangePicker)` → `Tabs` → KPI `StatCard`s + `ChartCard`s.

---

## 6. New-page checklist

1. [ ] Read this doc + the module's api contract.
2. [ ] `@mxid/shared/api/<module>.ts` for endpoints (mirror backend).
3. [ ] Missing kit component? Build into `@mxid/shared/ui`, register in §2.
4. [ ] Use the §5 template; reuse components, don't invent layout.
5. [ ] Three states + destructive confirm + toast + validation.
6. [ ] Colors/spacing/radius via tokens; status via tone helpers.
7. [ ] Zero hardcoded copy (i18n).
8. [ ] `tsc -b` green; verify light + dark.
9. [ ] Commit (English, Conventional Commits, no AI attribution).

---

## 7. Tailwind v4 gotchas (bit us, don't repeat)

1. **`@theme` colors must NOT include `/ <alpha-value>`.** Write
   `--color-surface: rgb(var(--surface))`. The `/ <alpha-value>` form is a v3
   `tailwind.config` idiom; in v4 it leaks the literal placeholder into solid
   utilities (`bg-surface` → invalid → transparent). Opacity modifiers still work
   (v4 uses `color-mix`).
2. **Dark shim: flat selectors, no `&` nesting.** Lightning CSS silently drops
   nested rules with escaped `:hover` / `\/`, so hover/opacity variants never
   compile. Write `.dark main .hover\:bg-gray-200:hover { … }` flat.
3. **macOS Docker bind-mount misses new-file fs events.** After adding a new
   `.tsx`, its unique classes may not be scanned — `docker restart
   mxid-console-vite mxid-portal-vite` to force a rescan.
