const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_DIR = path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'homeworks.db');

fs.mkdirSync(DB_DIR, { recursive: true });

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`);

app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// GET all data
app.get('/api/data', (req, res) => {
  const row = db.prepare('SELECT value FROM store WHERE key = ?').get('homeworks');
  if (!row) return res.json({ projects: [], customCats: [], contractors: [], properties: [] });
  res.json(JSON.parse(row.value));
});

// PUT all data
app.put('/api/data', (req, res) => {
  db.prepare('INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)').run('homeworks', JSON.stringify(req.body));
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`HomeWorks running → http://localhost:${PORT}`);
});
