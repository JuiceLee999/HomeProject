# HomeWorks — Project Tracker

## Project Overview

HomeWorks is a single-file HTML application for tracking home improvement projects. It is currently a **self-contained `home_projects.html` file** with all HTML, CSS, and JavaScript inline. There is no build system, no backend, and no dependencies beyond Google Fonts (loaded via CDN).

All data is persisted in the browser's `localStorage` under the key `homeworks_v3`.

---

## Current File Structure

```
home_projects.html   ← entire app: HTML + CSS + JS in one file
CLAUDE.md            ← this file
```

When refactoring, a natural split would be:
```
index.html
css/
  styles.css
js/
  app.js
  data.js
  ui.js
```

---

## Data Model

All data is stored as JSON in `localStorage` under key `homeworks_v3`:

```json
{
  "projects": [...],
  "customCats": [...],
  "contractors": [...]
}
```

### Project object
```js
{
  id: Number,           // Date.now() timestamp, used as unique ID
  name: String,
  note: String,         // short auto-generated summary (first 90 chars of description)
  description: String,  // full scope of work
  category: String,     // from DEFAULT_CATS or customCats
  priority: "high" | "medium" | "low",
  status: "todo" | "someday" | "done",
  cost: String,         // freeform, e.g. "$350" — parsed with parseCost()
  done: Boolean,        // mirrors status === 'done', legacy field
  created: Number,      // timestamp
  modified: Number,     // timestamp, updated on every savePanel()
  startDate: String,    // ISO date "YYYY-MM-DD" or ""
  endDate: String,      // ISO date "YYYY-MM-DD" or "" — used for overdue logic
  urls: [               // parts & material links
    { label: String, href: String }
  ],
  notes: String,        // freeform scratchpad
  subtasks: [           // checklist steps
    { id: Number, text: String, done: Boolean }
  ],
  contractorId: Number | null   // references contractors[].id
}
```

### Contractor object
```js
{
  id: Number,       // Date.now() timestamp
  company: String,  // company name (required)
  type: String,     // e.g. "Plumber", "Electrician", "Painter", etc.
  poc: String,      // point of contact name
  phone: String,
  email: String
}
```

### Custom categories
`customCats` is a plain `String[]`. Default categories are defined in the constant `DEFAULT_CATS` and never stored.

```js
const DEFAULT_CATS = [
  'Kitchen','Bathroom','Bedroom','Living Room','Basement',
  'Garage','Exterior','Yard','HVAC','Electrical','Plumbing','Other'
];
```

---

## Key JavaScript Functions

### Data
| Function | Description |
|---|---|
| `save()` | Serializes `{projects, customCats, contractors}` to localStorage and calls `render()` |
| `parseCost(s)` | Strips non-numeric chars and returns a float, or `null` |
| `datePlus(days)` | Returns an ISO date string N days from today |
| `timeAgo(ts)` | Human-readable relative time from a timestamp |
| `fmtDate(d)` | Formats ISO date to "Jan 5" style |
| `escHtml(s)` | HTML-escapes a string for safe DOM injection |

### Projects
| Function | Description |
|---|---|
| `addProject()` | Reads the quick-add form, creates a project, closes the form, saves, opens the detail panel |
| `toggleDone(id, e)` | Toggles status between `'done'` and `'todo'` |
| `deleteProject(id, e)` | Confirms and deletes; closes panel if open |
| `duplicateProject(id, e)` | Deep-copies a project, resets status/subtasks, inserts after original |
| `duplicateFromPanel()` | Calls `duplicateProject` for the currently open panel project |

### UI / Rendering
| Function | Description |
|---|---|
| `render()` | Full re-render: updates stats, budget strip, sorts+filters projects, rebuilds project list HTML |
| `cardHTML(p, today, soon)` | Returns HTML string for a single project card |
| `section(label, count, key)` | Returns collapsible section header + opens `<div class="section-body">` |
| `toggleSection(key)` | Toggles collapse state for a section without full re-render |
| `setFilter(f, btn)` | Sets `currentFilter`, updates active button, calls `render()` |

### Detail Panel
| Function | Description |
|---|---|
| `openPanel(id)` | Populates all panel fields from a project object and opens the panel |
| `closePanel()` | Removes `panel-open` class, clears `openId`, re-renders |
| `savePanel()` | Reads all panel fields back into the project object, updates `modified`, calls `save()` |

### Add Form
| Function | Description |
|---|---|
| `toggleAddForm()` | Opens/closes the collapsible add form dropdown in the toolbar |
| `closeAddForm()` | Closes the add form and resets the button state |

### Categories
| Function | Description |
|---|---|
| `buildCatSelects()` | Rebuilds both the quick-add and panel category `<select>` elements |
| `handleCatChange(sel)` | Detects "+ New Category…" selection and shows custom input |
| `applyCustomCat(name)` | Adds to `customCats`, rebuilds selects |
| `cancelCustomCat()` | Hides custom input, restores select |

### Contractors
| Function | Description |
|---|---|
| `buildContractorSelect(selectedId)` | Populates the contractor dropdown in the panel |
| `handleContractorSelect(sel)` | Updates `currentContractorId` and renders the contractor card |
| `renderContractorCard(id)` | Shows/hides the contractor detail card below the dropdown |
| `clearContractor()` | Removes contractor assignment from current panel |
| `showContractorForm()` | Shows the inline new-contractor form |
| `hideContractorForm()` | Hides and resets the contractor form |
| `saveNewContractor()` | Validates, saves to `contractors[]`, assigns to current project, persists immediately |

### Subtasks
| Function | Description |
|---|---|
| `rebuildSubtaskDOM()` | Re-renders the subtask list from `subtaskRows[]` |
| `addSubtaskRow()` | Appends a new empty subtask and focuses the input |
| `removeSubtask(i)` | Removes subtask at index i |
| `collectSubtasks()` | Filters and maps `subtaskRows` into clean objects for saving |
| `updateSubProgress()` | Updates the "X of Y complete" progress label |

### URLs
| Function | Description |
|---|---|
| `rebuildUrlDOM()` | Re-renders the URL list from `urlRows[]` |
| `addUrlRow()` | Appends a new empty URL row |
| `removeUrl(i)` | Removes URL at index i |
| `collectUrls()` | Filters empty rows and maps `urlRows` into clean objects |

---

## UI Layout

```
<header>                         ← sticky, dark, shows stats + total cost
<main>
  <div.toolbar>                  ← "+ New Project" btn | filters | sort
  <div.add-dropdown>             ← collapsible quick-add form (slides down)
  <div.budget-strip>             ← total cost | active | completed | progress bar
  <div#project-list>
    <div.section-head>           ← collapsible: "To Do", "Someday", "Completed"
    <div.section-body>
      <div.project-card>         ← click to open panel
      ...
</main>

<div.overlay>                    ← semi-transparent backdrop when panel open
<div.detail-panel>               ← fixed right-side panel (500px wide)
  <div.panel-header>             ← editable title, modified timestamp, close btn
  <div.panel-body>
    - Category + Priority
    - Cost + Status
    - Timeframe (start → end date)
    - Description (textarea)
    - Subtasks / Checklist
    - Parts & Material Links (URL list)
    - Contractor (select + new form)
    - Notes (textarea)
  <div.panel-footer>             ← Duplicate btn | Save Changes | "✓ Saved" flash
```

---

## Design System

### Fonts (Google Fonts)
- **Playfair Display** — headings, panel title
- **DM Mono** — labels, tags, monospace UI elements
- **DM Sans** — body text, inputs

### CSS Variables
```css
--bg: #f5f0e8          /* warm off-white page background */
--paper: #fdfaf4       /* card/panel backgrounds */
--ink: #1a1209         /* near-black text */
--muted: #7a6e5f       /* secondary text, labels */
--rule: #d6cebf        /* borders, dividers */
--accent: #c8440a      /* burnt orange — primary action color */
--accent-light: #f0d5c8
--green: #2d6a4f
--green-light: #c8e6d8
--yellow: #e9a319
--yellow-light: #faeac8
--blue: #1a4a7a
--blue-light: #c8daf0
--red: #b91c1c
--red-light: #fee2e2
--orange: #c2410c
--orange-light: #ffedd5
--panel-w: 500px       /* detail panel width */
```

### Priority color coding
- **High** → accent (burnt orange) left border on card
- **Medium** → yellow left border
- **Low** → green left border
- **Overdue** → red left border (overrides priority)
- **Due soon** → orange left border (overrides priority, yields to overdue)

---

## Keyboard Shortcuts
| Shortcut | Action |
|---|---|
| `Cmd/Ctrl + S` | Save the open detail panel |
| `Escape` | Close the detail panel or close the add form |
| `Enter` (in name/cost field) | Submit the quick-add form |
| `Enter` (in custom cat input) | Confirm new category name |

---

## Overdue / Due Soon Logic
- **Overdue**: `p.endDate < today` and status is not `done`
- **Due soon**: `p.endDate >= today && p.endDate <= today + 7 days` and status is not `done`
- Both are computed in `render()` using today's ISO date string and `datePlus(7)`

---

## Known Gaps / Suggested Next Features
- No backend — data is browser-local only; clearing cache loses everything
- No edit/delete UI for saved contractors
- No data export or import
- No image/photo attachments
- No dark mode
- Mobile layout works but toolbar gets cramped on small screens
- Contractor type is a fixed list — no custom types yet
- No ability to view all projects assigned to a specific contractor
