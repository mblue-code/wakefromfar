# WakeFromFar Admin UI/UX Refactor Plan (Revised)

> Revised 2026-03-08 — updated to reflect scheduled wakes, device memberships, and disabled invites/pilot-metrics.

## Current State Analysis

### Architecture
- **Single file**: `backend/app/admin_ui.py` (3,186 lines) — all HTML, CSS, JS, i18n, routes
- **No frameworks**: Pure inline CSS + vanilla JS, server-rendered HTML via Python f-strings
- **Theme support**: Light/dark via CSS custom properties + localStorage
- **i18n**: EN/DE with ~240+ keys
- **Responsive**: Single breakpoint at 768px

### Pages (13 active + 2 disabled)

| Page | Route | Complexity | Notes |
|------|-------|------------|-------|
| Login | `/login` | Low | Standalone, own CSS |
| Dashboard | `/` | Medium | 4 stat cards + 2 tables |
| Users | `/users` | Medium | Create form + table w/ inline edit |
| Devices | `/devices` | High | Create grid form + table w/ 9-input inline edit |
| Scheduled Wakes | `/scheduled-wakes` | High | Filter form + jobs table + runs table + separate create/edit pages |
| Device Access | `/device-memberships` | High | Grant form w/ 5 permission checkboxes + table w/ inline checkbox edit |
| Wake Logs | `/wake-logs` | Low | Filter form + table |
| Power Logs | `/power-check-logs` | Low | Filter form + table |
| Audit Logs | `/audit-logs` | Low | Table only |
| Diagnostics | `/diagnostics` | Medium | 3 info tables |
| Discovery | `/discovery` | Very High | Scan form + 3 tables + bulk import + docker filter |
| Metrics | `/metrics` | Low | Table only |
| Invites | `/invites` | — | Disabled, redirects |
| Pilot Metrics | `/pilot-metrics` | — | Disabled, redirects |

### Current Visual Issues

| Area | Problem |
|------|---------|
| **Layout density** | Tables crammed with inline forms (devices: 12 cols + 9-input edit; memberships: 12 cols + checkbox grid) |
| **Form placement** | Create forms sit above tables with no visual separation — one continuous block |
| **Inline editing** | Device update = 9 stacked inputs in a table cell; membership update = 5 checkboxes + sort input inline |
| **Inconsistent spacing** | Mix of inline `style=` and CSS classes; `gap:4px`, `gap:6px`, `gap:8px` randomly |
| **Visual hierarchy** | h2 headings at 1.1rem barely distinguishable from body text |
| **Stat cards** | 4 plain white boxes — no icon, no color accent (Users, Devices, Scheduled Wakes, Device Access) |
| **Tables** | No hover states, no zebra striping, UUIDs shown in full (unreadable) |
| **Buttons** | Primary actions (Save/Create) vs destructive (Delete) vs toggle (Enable/Disable) not differentiated |
| **Mobile** | Sidebar collapses to horizontal wrapping links — chaotic with 12+ nav items |
| **Login page** | Functional but minimal — no branding beyond text |
| **Discovery page** | Most complex page: 4 tables + forms — overwhelming wall of data |
| **Scheduled wakes** | Create/edit are separate pages but look identical to main layout — no visual "form page" feel |
| **Permission checkboxes** | Device memberships checkbox grid has no visual grouping or explanation |
| **Flash messages** | Auto-dismiss at 4s too fast for errors; no urgency distinction |
| **Empty states** | No message when tables have zero rows |
| **Badge colors** | Hardcoded without semantic system — no legend |

---

## Design Principles

1. **Zero new dependencies** — keep self-contained single-file approach
2. **Preserve all functionality** — every button, form, filter, permission checkbox stays
3. **Reduce cognitive load** — progressive disclosure, group related actions
4. **Consistent visual language** — unified spacing, color system, component patterns
5. **Mobile-usable** — admin tasks should work on tablet/phone in emergencies

---

## Color System

### Light Theme

```
Background:     #f8f9fc
Surface:        #ffffff
Surface-alt:    #f1f3f8 (alternating rows, secondary panels)
Border:         #e2e5ed
Border-subtle:  #eef0f5

Text-primary:   #1a1d26
Text-secondary: #5a6178
Text-muted:     #8b92a8

Accent:         #4f6ef7 (primary actions)
Accent-hover:   #3b5ae0
Accent-subtle:  #eef1fe (accent backgrounds)

Success:        #22a55a
Success-bg:     #edfbf3
Warning:        #e5930a
Warning-bg:     #fef8ec
Danger:         #e53535
Danger-bg:      #fef0f0
Info:           #3b82f6
Info-bg:        #eff6ff
```

### Dark Theme

```
Background:     #0c0e14
Surface:        #181c28
Surface-alt:    #1e2333
Border:         #2a3045
Border-subtle:  #232840

Text-primary:   #e8eaf0
Text-secondary: #9da3b8
Text-muted:     #6b7290

Accent:         #6b8aff
Accent-hover:   #8da4ff
Accent-subtle:  #1e2545

Success:        #34d17a
Warning:        #f5a623
Danger:         #f05555
Info:           #60a5fa
```

### Semantic Badge Colors

| Status | Color | Usage |
|--------|-------|-------|
| `sent` / `on` / `completed` / `enabled` | Success green | Positive outcomes |
| `already_on` / `running` | Info blue | Informational |
| `failed` / `error` / `disabled` | Danger red | Failures & disabled states |
| `off` / `unknown` / `pending` | Muted gray | Neutral/unknown |
| `tcp` / `icmp` | Distinct purples/teals | Method identifiers |
| `admin` | Accent blue | Role highlight |
| `user` | Muted | Default role |
| `high` | Success green | WoL confidence |
| `medium` | Warning amber | WoL confidence |
| `low` | Danger red | WoL confidence |

---

## Spacing Scale

```
--space-1: 0.25rem   (4px)
--space-2: 0.5rem    (8px)
--space-3: 0.75rem   (12px)
--space-4: 1rem      (16px)
--space-5: 1.5rem    (24px)
--space-6: 2rem      (32px)
--space-8: 3rem      (48px)
```

---

## Typography Scale

```
--text-xs:   0.75rem   (12px) — badges, captions
--text-sm:   0.8125rem (13px) — table cells, secondary text
--text-base: 0.875rem  (14px) — body text, form labels
--text-md:   1rem      (16px) — topbar title, nav items
--text-lg:   1.125rem  (18px) — section headings (h2)
--text-xl:   1.5rem    (24px) — page titles
--text-2xl:  2rem      (32px) — stat numbers
```

---

## Component Redesign

### 1. Sidebar

**Changes:**
- Add section group labels ("MANAGEMENT", "SCHEDULING", "LOGS", "SYSTEM") as small uppercase muted text
- Left accent bar (3px) on active nav item + background highlight
- Slightly increase padding for touch targets
- Sidebar footer with "Admin Panel" label

```
┌──────────────────────┐
│ ⚡ WakeFromFar       │
│                      │
│ MANAGEMENT           │
│ ▸ Dashboard          │  ← active: left accent bar + bg
│   Users              │
│   Devices            │
│                      │
│ SCHEDULING           │
│   Scheduled Wakes    │
│   Device Access      │
│                      │
│ LOGS                 │
│   Wake Logs          │
│   Power Logs         │
│   Audit Logs         │
│                      │
│ SYSTEM               │
│   Diagnostics        │
│   Discovery          │
│   Metrics            │
│                      │
│         Admin Panel  │
└──────────────────────┘
```

### 2. Topbar

**Changes:**
- Compact lang switch
- Clean spacing between user info, theme toggle, logout

```
┌─────────────────────────────────────────────────────────┐
│ Dashboard                          🌙  EN|DE  admin ↗  │
└─────────────────────────────────────────────────────────┘
```

### 3. Dashboard Stat Cards

**Current:** 4 cards — Users, Devices, Scheduled Wakes, Device Access

**Changes:**
- Colored left border accent per card
- Subtle icon per stat (unicode)
- Larger number, smaller label

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ 👥           │  │ 💻           │  │ ⏰           │  │ 🔑           │
│     12       │  │     8        │  │     5        │  │     24       │
│   Users      │  │  Devices     │  │  Schedules   │  │ Device Access│
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
  blue accent      green accent     amber accent     purple accent
```

### 4. Tables

**Changes:**
- Zebra striping (alternate row background)
- Row hover highlight
- Truncate UUIDs/IDs to first 8 chars with `title` for full value
- Wrap tables in `<article>` for card styling
- Empty state row: "No records found" centered, muted

```css
tbody tr:nth-child(even) { background: var(--surface-alt); }
tbody tr:hover { background: var(--accent-subtle); }
```

### 5. Forms — Create/Edit Separation

**Create forms:** Wrap in `<article>` card with heading, clear visual boundary.

**Device inline edit:** Replace 9-input stacked form in table cell with "Edit" button → expanded row below.

```
┌──────────────────────────────────────────────────────────────┐
│ ID  │ Name    │ MAC              │ State │ Method │ Actions  │
├──────────────────────────────────────────────────────────────┤
│ a3f │ mypc    │ AA:BB:CC:DD:EE:FF│ 🟢 on │ tcp    │ ✏️ 🗑️ ⚡│
├──────────────────────────────────────────────────────────────┤
│ ▼ Edit: mypc                                                │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │  Name [mypc     ]  Display [My PC   ]  MAC [AA:BB:...]  │ │
│ │  Interface [eth0]  Source IP [      ]  CIDR [         ]  │ │
│ │  Check: [tcp ▾] Target [192.168.1.5]  Port [22       ]  │ │
│ │                                          [Cancel] [Save] │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

**Device memberships inline edit:** Keep checkbox grid inline but add visual grouping — wrap checkboxes in a `.permission-group` with subtle background and border-radius.

**User inline edit:** Keep compact role dropdown + password inline.

### 6. Buttons

| Type | Style | Usage |
|------|-------|-------|
| Primary | Solid accent bg, white text | Create, Save, Login, Run, Grant Access |
| Secondary | Border only, text color | Cancel, Test, Filter, Merge |
| Danger | Red border, red text; solid red on hover | Delete, Remove Access |
| Toggle | Green outline when enabled, muted when disabled | Enable/Disable schedule |
| Small | Reduced padding, smaller font | Inline table actions |

```css
.btn-primary { background: var(--accent); color: #fff; border: none; }
.btn-danger  { background: transparent; color: var(--danger); border: 1px solid var(--danger); }
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-toggle-on  { color: var(--success); border-color: var(--success); }
.btn-toggle-off { color: var(--muted); border-color: var(--border); }
.btn-sm { padding: .3rem .6rem; font-size: var(--text-xs); }
```

### 7. Flash Messages

- Error messages: don't auto-dismiss (require manual close)
- Success messages: auto-dismiss after 5s
- Left border accent (4px solid green/red)
- Icon prefix (✓ success, ✕ error)

### 8. Login Page

- Subtle box-shadow on card
- Increase max-width to 400px
- Focus states with accent border + subtle glow
- Add favicon image above title

### 9. Mobile Responsive

- Sidebar: hamburger toggle (hidden by default on mobile)
- Tables: horizontal scroll with sticky first column
- Stat cards: 2-col at 768px, 1-col at 480px
- Forms: stack all inputs vertically on mobile
- Permission checkbox grids: 1-col on mobile (already partially done via `.membership-permissions`)
- Add breakpoint at 480px

### 10. Discovery Page

- Collapsible sections via `<details>` for Runs, Candidates, Events
- Sender bindings as pill tags
- Scan form in `<fieldset>` with `<legend>`

### 11. Scheduled Wakes Pages (NEW)

**List page:**
- Filter form wrapped in `<article>` with subtle styling
- Jobs table: use toggle button styling for enable/disable
- Runs table below, collapsible via `<details>`
- Day-of-week display as small pill tags (Mon, Tue, etc.)

**Create/Edit pages:**
- Form wrapped in `<article>` card with clear heading
- Day-of-week checkboxes: styled as selectable pill buttons rather than raw checkboxes
- Timezone input: add helper text
- Back/cancel link clearly visible

### 12. Device Access Page (NEW)

**Grant form:**
- Wrap in `<article>` card
- Permission checkboxes: group visually with label descriptions
- Use `.permission-group` with subtle background, rounded corners

**Table:**
- Boolean permission columns: show as colored check/cross icons instead of raw checkbox inputs
- Inline edit: permission checkboxes get `.permission-group` styling
- Sort order: small numeric input

---

## Implementation Phases

### Phase 1: Foundation (CSS variables + spacing + typography)
**Effort: Low | Impact: Medium**

1. Replace all color values in CSS (`:root` and `[data-theme="dark"]`) with new palette
2. Add spacing scale variables and apply consistently across all padding/margin/gap values
3. Add typography scale variables and reference in font-size declarations
4. Add global `input:focus` and `select:focus` styles
5. Replace inline `style=` attributes with CSS classes (`.form-inline`, `.form-grid`, `.form-grid-4`, `.form-grid-2`)
6. Incorporate existing classes (`.membership-create-form`, `.membership-permissions`, `.checkbox-group`, `.checkbox-item`, `.stacked-cell`) into the new spacing/color system

**Scope:** CSS section in `_layout()` + login page CSS + all inline styles across 13 pages

### Phase 2: Components (buttons, badges, flash, tables)
**Effort: Medium | Impact: High**

1. Button hierarchy: `.btn-primary`, `.btn-secondary`, `.btn-danger`, `.btn-toggle-on`, `.btn-toggle-off`, `.btn-sm`
2. Badge color system: update `_badge()` with semantic mapping including new states (`enabled`, `disabled`, `running`, `pending`)
3. Flash messages: icons, timing (5s success / no auto-dismiss error), left accent border
4. Table zebra striping + hover for all tables
5. UUID truncation: `_short_id()` helper, apply across all pages
6. Empty state rows for all tables (add i18n key `empty_state` / `empty_state` DE)
7. Wrap all `<figure><table>` in `<article>` cards

**Scope:** CSS + `_badge()` function + all page templates (13 pages)

### Phase 3: Layout (sidebar, topbar, stat cards, form cards)
**Effort: Medium | Impact: High**

1. Sidebar: section labels (MANAGEMENT / SCHEDULING / LOGS / SYSTEM), active accent bar, footer
2. Topbar: compact layout
3. Dashboard stat cards: 4 cards with colored accent + icons
4. Wrap all create/filter forms in `<article>` cards
5. Permission checkbox visual grouping (`.permission-group`)

**Scope:** `_layout()` sidebar/topbar + dashboard + all form wrappers + memberships page

### Phase 4: Forms & Interactions
**Effort: High | Impact: High**

1. Device table: expand/collapse edit row via JS toggle (replace inline 9-input stack)
2. User table: compact inline form styling
3. Scheduled wakes: day-of-week pill styling, toggle button for enable/disable
4. Discovery page: `<details>` collapsible sections, fieldset for scan form
5. Device memberships: boolean columns as check/cross icons in table view

**Scope:** Devices page + users page + scheduled-wakes pages + discovery page + memberships page + JS section

### Phase 5: Mobile & Polish
**Effort: Medium | Impact: Medium**

1. Hamburger toggle for sidebar on mobile
2. 480px breakpoint for stat cards + forms
3. Login page: shadow, focus glow
4. Transitions/animations (expand/collapse, hover)
5. `title` attributes for truncated data
6. Dark theme audit for all new variables and components
7. Test all 13 pages in both themes at 3 breakpoints (desktop, 768px, 480px)

**Scope:** CSS responsive rules + JS hamburger + login page + dark theme pass

---

## New i18n Keys Needed

```yaml
# English
empty_state: "No records found"
nav_section_management: "MANAGEMENT"
nav_section_scheduling: "SCHEDULING"
nav_section_logs: "LOGS"
nav_section_system: "SYSTEM"

# German
empty_state: "Keine Einträge gefunden"
nav_section_management: "VERWALTUNG"
nav_section_scheduling: "PLANUNG"
nav_section_logs: "PROTOKOLLE"
nav_section_system: "SYSTEM"
```

---

## What NOT to Change

- No external CSS/JS libraries
- No template engine (keep f-string rendering)
- No new routes or API changes
- No changes to form field names or POST behavior
- No changes to authentication/session logic
- No file splitting (keep single-file approach)
- No changes to the permission model or scheduled wake logic
- Existing i18n keys stay unchanged — only add new ones

---

## Summary

| Phase | Changes | Effort | Impact |
|-------|---------|--------|--------|
| 1. Foundation | Colors, spacing, typography, focus states, inline→class | Low | Medium |
| 2. Components | Buttons, badges, tables, flash, empty states, UUID truncation | Medium | High |
| 3. Layout | Sidebar sections, topbar, stat cards, form cards, permission groups | Medium | High |
| 4. Forms | Device expand/edit, schedule pills, discovery collapsible, toggle buttons | High | High |
| 5. Mobile & Polish | Hamburger, 480px breakpoint, login, transitions, dark theme audit | Medium | Medium |

Total: 5 phases, all within `admin_ui.py`, zero new dependencies, covers all 13 active pages.
