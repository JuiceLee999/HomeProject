# Changelog

All notable changes to HomeWorks will be documented here.

---

## [Unreleased]

---

## [1.4.0] - 2026-03-25
### Fixed
- **Category always saving as "Kitchen"** — `buildCatSelects()` rebuilds the category `<select>` innerHTML on every `render()` call, which resets it to the first option. Now restores the open project's saved category after each rebuild.

---

## [1.3.0] - 2026-03-25
### Added
- **Contractor Manager** — new 🔨 Contractors button in the toolbar opens a modal listing all saved contractors with the ability to edit and delete each one.
  - Inline edit form per contractor (company, type, point of contact, phone, email)
  - Delete with confirmation warning if the contractor is currently assigned to any projects; automatically unassigns affected projects
  - Project count shown per contractor ("📋 3 projects")
  - Panel contractor card and dropdown refresh automatically after edits

---

## [1.2.0] - 2026-03-25
### Added
- **HTTPS** — nginx reverse proxy with a self-signed SSL certificate; HTTP on port 80 auto-redirects to HTTPS on port 443.

### Infrastructure
- **SQLite database** via `better-sqlite3` — all project data now persists in `/var/www/HomeProject/db/homeworks.db` on the server instead of the browser's `localStorage`.
- **Express backend** (`server.js`) serves the frontend and exposes `GET /api/data` and `PUT /api/data` endpoints.
- **pm2** process manager keeps the app running and restarts it on server reboot.
- **Deploy pipeline** — `push-prod.sh` merges `dev` → `main`, pushes to GitHub, SSHs into the server, pulls latest, runs `npm install`, and restarts via pm2.
- **Branch strategy** — `dev` for local development, `main` for production.
- Production server: `159.203.111.124`

---

## [1.1.0] - 2026-03-25
### Added
- **Properties** — assign projects to a named property (e.g. "Main House", "Rental Unit"). Properties have an optional address field.
  - New "Property" field in the project detail panel with inline "+ New Property…" form
  - Property filter dropdown in the toolbar — stacks with existing status/priority filters
  - Purple 🏠 property tag shown on project cards
  - Property included in PDF export
  - Properties persisted alongside projects, contractors, and custom categories

- **PDF Export** — ⬇ PDF button in the panel footer exports the current project as a print-ready page in a new tab and auto-triggers the browser print/save dialog.
  - Includes: name, tags, dates, description, checklist, material links, contractor card, notes, inline photo thumbnails, and document list
  - Export date stamped at the bottom

- **Photo & Document Attachments** — 📎 Attachments section at the bottom of every project panel.
  - Supports images, PDFs, Word, Excel, CSV, and text files (up to 5MB each)
  - Images show as thumbnails — click to open in a new tab
  - Non-images show a file type icon — click to download
  - Stored as base64 in the project's `attachments[]` array

- **Delete button** — 🗑 button in the panel footer deletes the current project after confirmation.

- **Dark mode** — 🌙/☀ toggle in the header switches between light and dark themes. Preference persists in `localStorage`.

---

## [1.0.0] - 2026-03-25
### Initial Release
- Single-file HTML app (`home_projects.html`) — no build tools, no backend, no dependencies beyond Google Fonts
- **Projects** — add, edit, duplicate, and delete home improvement projects
- **Quick-add form** — collapsible dropdown in the toolbar for fast project creation
- **Detail panel** — fixed right-side panel with full project editing
- **Subtasks / Checklist** — per-project checklist with progress tracking
- **Material Links** — attach labeled URLs to any project
- **Contractors** — save contractor contact info (company, type, POC, phone, email) and assign to projects
- **Custom categories** — extend the default category list inline
- **Priority & Status** — High / Medium / Low priority; To Do / Someday / Done status
- **Due dates** — overdue (red) and due-soon (orange) highlighting on cards
- **Budget strip** — total estimated cost, active project count, completion progress bar
- **Filters** — All, To-Do, Someday, Done, High, Medium, Low, Overdue
- **Sort** — by date added, priority, due date, cost, last modified, or name A→Z
- **Collapsible sections** — To Do / Someday / Completed sections collapse independently
- **Keyboard shortcuts** — `Ctrl/Cmd+S` to save panel, `Esc` to close panel or add form, `Enter` to submit quick-add
- **Data persistence** — `localStorage` under key `homeworks_v3`
- **Responsive** — mobile layout with full-width panel on small screens
