# HomeWorks — Project Tracker

A single-file home improvement project tracker. No build tools, no backend, no dependencies — just open the HTML file in a browser.

All data is saved in your browser's `localStorage`.

---

## Features

- **Projects** — add, edit, duplicate, and delete home improvement projects
- **Properties** — assign projects to properties (main house, rental, cabin, etc.) and filter by property
- **Subtasks** — checklist steps per project with progress tracking
- **Contractors** — save contractor contact info and assign to projects
- **Material Links** — attach part/product URLs to any project
- **Attachments** — upload photos and documents (PDF, Word, Excel, images) per project
- **PDF Export** — export any project to a print-ready PDF with one click
- **Priority & Status** — High / Medium / Low priority with To Do / Someday / Done status
- **Due Dates** — overdue and due-soon highlighting on cards
- **Budget Tracking** — total estimated cost across all projects
- **Filters** — filter by status, priority, overdue, or property
- **Sort** — by date added, priority, due date, cost, last modified, or name
- **Dark Mode** — toggle with the 🌙 button in the header; preference is remembered
- **Keyboard Shortcuts** — `Ctrl/Cmd+S` to save, `Esc` to close panel

---

## Getting Started

1. Download `home_projects (1).html`
2. Open it in any modern browser
3. Your data saves automatically in `localStorage` — no account or internet required

> **Note:** Clearing your browser cache will erase your data. Use the browser's built-in "Save as PDF" (via the ⬇ PDF button) to keep permanent records of projects.

---

## Data Model

Projects, contractors, properties, and custom categories are all stored as JSON under the localStorage key `homeworks_v3`.

```json
{
  "projects": [...],
  "customCats": [...],
  "contractors": [...],
  "properties": [...]
}
```

See `CLAUDE.md` for the full data model and function reference.

---

## Tech Stack

- Vanilla HTML + CSS + JavaScript (no frameworks)
- Google Fonts — Playfair Display, DM Mono, DM Sans
- `localStorage` for persistence
- `FileReader` API for photo/document attachments (stored as base64)
