# WakeFromFar Admin UI/UX Refactor Plan

## Current State Analysis

### Architecture
- **Single file**: `backend/app/admin_ui.py` (2,229 lines) — all HTML, CSS, JS, i18n, routes
- **No frameworks**: Pure inline CSS + vanilla JS, server-rendered HTML via Python f-strings
- **Theme support**: Light/dark via CSS custom properties + localStorage
- **i18n**: EN/DE with ~200 keys
- **Responsive**: Single breakpoint at 768px

### Current Visual Issues

| Area | Problem |
|------|---------|
| **Layout density** | Tables are crammed with inline forms (devices page has 12 columns + edit form per row) |
| **Form placement** | Create forms sit above tables with no visual separation — looks like one continuous block |
| **Inline editing** | Device update form = 9 stacked inputs inside a table cell — unusable on smaller screens |
| **Inconsistent spacing** | Mix of inline `style=` attributes and CSS classes; `gap:4px`, `gap:6px`, `gap:8px` randomly |
| **Visual hierarchy** | h2 headings at 1.1rem are barely distinguishable from body text |
| **Stat cards** | Dashboard cards are plain white boxes — no icon, no trend, no color accent |
| **Tables** | No hover states, no zebra striping, UUIDs shown in full (unreadable) |
| **Buttons** | All buttons look identical — primary actions (Save/Create) vs destructive (Delete) not differentiated |
| **Mobile** | Sidebar collapses to horizontal wrapping links — becomes chaotic with 10+ nav items |
| **Login page** | Functional but minimal — no visual warmth, no branding beyond text |
| **Discovery page** | Most complex page with 4 tables + forms — overwhelming wall of data |
| **Flash messages** | Auto-dismiss at 4s is too fast for error messages; no distinction in urgency |
| **Empty states** | No empty state messages when tables have zero rows |
| **Topbar** | Cluttered with user info, lang switch, theme toggle, logout all in a row |
| **Badge colors** | Hardcoded without semantic meaning — no legend, colors don't follow a system |

---

## Design Principles

1. **Zero new dependencies** — keep the self-contained single-file approach
2. **Preserve all functionality** — every button, form, filter stays
3. **Reduce cognitive load** — progressive disclosure, group related actions
4. **Consistent visual language** — unified spacing scale, color system, component patterns
5. **Mobile-usable** — admin tasks should work on tablet/phone in emergencies

---

## Color System

### Light Theme

```
Background:     #f8f9fc (slightly warmer than current #f5f7fb)
Surface:        #ffffff
Surface-alt:    #f1f3f8 (for alternating rows, secondary panels)
Border:         #e2e5ed
Border-subtle:  #eef0f5

Text-primary:   #1a1d26
Text-secondary: #5a6178
Text-muted:     #8b92a8

Accent:         #4f6ef7 (blue — primary actions)
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

### Semantic Badge Colors (both themes)

| Status | Color | Usage |
|--------|-------|-------|
| `sent` / `on` / `completed` | Success green | Positive outcomes |
| `already_on` | Info blue | Informational |
| `failed` / `error` | Danger red | Failures |
| `off` / `unknown` | Muted gray | Neutral/unknown |
| `tcp` / `icmp` | Distinct purples/teals | Method identifiers |
| `admin` | Accent blue | Role highlight |
| `user` | Muted | Default role |
| `high` | Success green | WoL confidence |
| `medium` | Warning amber | WoL confidence |
| `low` | Danger red | WoL confidence |

---

## Spacing Scale

Replace ad-hoc pixel values with a consistent scale:

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

### 1. Sidebar (low effort, high impact)

**Changes:**
- Add subtle icons (CSS-only, using unicode/emoji or simple SVG inline) before each nav label
- Add a visual group label above each nav section ("Management", "Logs", "System")
- Slightly increase padding for better touch targets
- Add a subtle bottom border/accent on active item instead of background-only highlight
- Sidebar footer: version or "Admin Panel" label at bottom

```
┌──────────────────────┐
│ ⚡ WakeFromFar       │
│                      │
│ MANAGEMENT           │
│ ▸ Dashboard          │  ← active: left accent bar + bg
│   Users              │
│   Devices            │
│   Assignments        │
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
│              v1.0    │
└──────────────────────┘
```

### 2. Topbar (simplify)

**Changes:**
- Move language switch into a dropdown or smaller icon-based toggle
- Group user info + logout into a single user menu area
- Keep theme toggle as icon button

```
┌─────────────────────────────────────────────────────────┐
│ Dashboard                          🌙  EN|DE  admin ↗  │
└─────────────────────────────────────────────────────────┘
```

### 3. Dashboard Stat Cards (high impact)

**Changes:**
- Add color accent (left border or top border with semantic color)
- Add subtle background tint per card
- Add a small icon per stat (unicode)
- Larger number, smaller label below

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ 👥           │  │ 💻           │  │ 🔗           │
│     12       │  │     8        │  │     24       │
│   Users      │  │  Devices     │  │ Assignments  │
└─────────────┘  └─────────────┘  └─────────────┘
  blue accent      green accent     purple accent
```

### 4. Tables (high impact)

**Changes:**
- Add zebra striping (alternate row background)
- Add row hover highlight
- Truncate UUIDs to first 8 chars with `title` attribute for full value
- Wrap tables in `<article>` for consistent card styling with subtle shadow
- Add empty state row: "No records found" centered, muted

```css
tbody tr:nth-child(even) { background: var(--surface-alt); }
tbody tr:hover { background: var(--accent-subtle); }
```

### 5. Forms — Create/Edit Separation (high impact)

**Current:** Create form directly above table, inline edit forms inside table cells.

**New approach:**
- **Create forms**: Wrap in `<article>` card with a heading, clear visual boundary
- **Inline edit (devices)**: Replace 9-input stacked form in table cell with a single "Edit" button that opens an expanded row or modal-like inline panel below the row
- **Simple inline edit (users)**: Keep role dropdown + password inline but style as a compact row with visual grouping

#### Device Edit Pattern (expanded row):

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
├──────────────────────────────────────────────────────────────┤
│ b7e │ server  │ ...              │ ...   │ ...    │ ...      │
└──────────────────────────────────────────────────────────────┘
```

### 6. Buttons (medium impact)

**Button hierarchy:**

| Type | Style | Usage |
|------|-------|-------|
| Primary | Solid accent bg, white text | Create, Save, Login, Run |
| Secondary | Border only, text color | Cancel, Test, Filter |
| Danger | Red border, red text; solid red on hover | Delete |
| Ghost | No border, text only | Dismiss, close |
| Small | Reduced padding, smaller font | Inline table actions |

```css
.btn         { padding: .45rem .85rem; border-radius: 8px; font-weight: 500; }
.btn-primary { background: var(--accent); color: #fff; border: none; }
.btn-danger  { background: transparent; color: var(--danger); border: 1px solid var(--danger); }
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-sm      { padding: .3rem .6rem; font-size: var(--text-xs); }
```

### 7. Flash Messages (low effort)

**Changes:**
- Error messages: don't auto-dismiss (require manual close)
- Success messages: auto-dismiss after 5s (increased from 4s)
- Add left border accent (green for success, red for error)
- Add icon prefix (✓ for success, ✕ for error)

### 8. Login Page (medium impact)

**Changes:**
- Add subtle gradient or pattern to background
- Increase card max-width slightly (400px)
- Add favicon/logo above title
- Add subtle box-shadow to card
- Improve input focus states (accent border + subtle glow)

```css
input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-subtle);
}
```

### 9. Mobile Responsive (medium effort)

**Changes:**
- Sidebar: hamburger toggle (hidden by default on mobile) instead of horizontal wrapping
- Tables: horizontal scroll with sticky first column
- Stat cards: stack to 1 column on very small screens (< 480px)
- Forms: stack all inputs vertically on mobile
- Add a second breakpoint at 480px

```
@media (max-width: 768px) {
  .sidebar { display: none; }  /* toggle via JS hamburger */
  .sidebar.open { display: flex; position: fixed; z-index: 50; }
}
@media (max-width: 480px) {
  .stat-cards { grid-template-columns: 1fr; }
}
```

### 10. Discovery Page (high effort, specific)

**Changes:**
- Collapsible sections: each table group (Runs, Candidates, Events) in its own `<details>` element
- Candidates table: reduce columns, move secondary data to expandable row
- Sender bindings: show as pill tags instead of comma-separated text
- Scan form: use fieldset with legend for visual grouping

---

## Implementation Phases

### Phase 1: Foundation (CSS variables + spacing + typography)
**Effort: Low | Impact: Medium**

1. Replace all color values with new CSS custom properties
2. Add spacing scale variables and apply consistently
3. Update typography scale
4. Add `input:focus` styles globally
5. Remove all inline `style=` attributes, move to CSS classes

**Files changed:** `admin_ui.py` (CSS section + HTML templates)

### Phase 2: Components (buttons, badges, flash, tables)
**Effort: Medium | Impact: High**

1. Implement button hierarchy (`.btn-primary`, `.btn-danger`, `.btn-sm`)
2. Update badge color system with semantic mapping
3. Improve flash messages (icons, timing, left accent)
4. Add table zebra striping, hover, truncated UUIDs
5. Add empty state rows for all tables
6. Wrap tables in `<article>` cards

**Files changed:** `admin_ui.py` (CSS + all page body templates)

### Phase 3: Layout (sidebar, topbar, cards)
**Effort: Medium | Impact: High**

1. Sidebar: add section labels, active indicator accent bar, footer
2. Topbar: simplify layout, compact lang/user area
3. Dashboard stat cards: colored accents, icons
4. Wrap create forms in `<article>` cards with headings

**Files changed:** `admin_ui.py` (`_layout` function + dashboard + forms)

### Phase 4: Forms & Interactions (inline edit, mobile)
**Effort: High | Impact: High**

1. Device table: replace inline stacked form with expand/collapse edit row (JS toggle)
2. User table: compact inline form styling
3. Discovery page: `<details>` collapsible sections
4. Mobile: hamburger toggle for sidebar
5. Mobile: add 480px breakpoint

**Files changed:** `admin_ui.py` (JS section + devices/discovery pages + CSS)

### Phase 5: Polish
**Effort: Low | Impact: Medium**

1. Login page: shadow, focus glow, gradient background
2. Add subtle transitions/animations (expand/collapse, hover)
3. Add `title` attributes for truncated data
4. Review and adjust dark theme for all changes
5. Test all pages in both themes at all breakpoints

**Files changed:** `admin_ui.py` (login page + CSS tweaks)

---

## What NOT to Change

- No external CSS/JS libraries (keep zero-dependency)
- No template engine (keep f-string rendering)
- No new routes or API changes
- No i18n key changes (unless adding empty state texts)
- No changes to form field names or POST behavior
- No changes to authentication/session logic
- No file splitting (keep single-file approach for now)

---

## Summary

| Phase | Changes | Effort | Impact |
|-------|---------|--------|--------|
| 1. Foundation | Colors, spacing, typography, focus states | Low | Medium |
| 2. Components | Buttons, badges, tables, flash, empty states | Medium | High |
| 3. Layout | Sidebar, topbar, stat cards, form cards | Medium | High |
| 4. Forms | Inline edit, discovery sections, mobile | High | High |
| 5. Polish | Login, transitions, dark theme audit | Low | Medium |

Total: ~5 phases, all within `admin_ui.py`, zero new dependencies.
