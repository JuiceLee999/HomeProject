const express = require('express');
const { Database } = require('node-sqlite3-wasm');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3001;
const DB_DIR = path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'cache.db');

fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    email          TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    last_logout_at INTEGER DEFAULT 0,
    created_at     INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS locations (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name    TEXT NOT NULL,
    UNIQUE(user_id, name),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    location    TEXT NOT NULL DEFAULT '',
    quantity    REAL NOT NULL DEFAULT 1,
    unit        TEXT NOT NULL DEFAULT 'pcs',
    value       REAL NOT NULL DEFAULT 0,
    brand       TEXT NOT NULL DEFAULT '',
    model       TEXT NOT NULL DEFAULT '',
    serial      TEXT NOT NULL DEFAULT '',
    condition   TEXT NOT NULL DEFAULT 'good',
    notes       TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]',
    qr_token    TEXT UNIQUE NOT NULL,
    image_data  TEXT DEFAULT NULL,
    created_at  INTEGER DEFAULT (strftime('%s','now')),
    modified_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── JWT secret ────────────────────────────────────────────────────────────────
let JWT_SECRET;
const secretRow = db.prepare('SELECT value FROM store WHERE key = ?').get('jwt_secret');
if (secretRow) {
  JWT_SECRET = secretRow.value;
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO store (key, value) VALUES (?, ?)').run(['jwt_secret', JWT_SECRET]);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function itemToJSON(row) {
  return { ...row, tags: JSON.parse(row.tags || '[]') };
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:", "blob:"],
      connectSrc:    ["'self'"],
      mediaSrc:      ["'self'", "blob:"],
      frameSrc:      ["'none'"],
      objectSrc:     ["'none'"],
      baseUri:       ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Serve jsQR from node_modules
app.get('/lib/jsqr.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules', 'jsqr', 'dist', 'jsQR.js'));
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    const userRow = db.prepare('SELECT last_logout_at FROM users WHERE id = ?').get(decoded.userId);
    if (userRow && decoded.iat * 1000 < (userRow.last_logout_at || 0)) {
      return res.status(401).json({ error: 'Token revoked' });
    }
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function isValidEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run([email, hash]);
  const userRow = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const token = jwt.sign({ userId: userRow.id, email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email });
});

app.post('/api/logout', verifyToken, (req, res) => {
  db.prepare('UPDATE users SET last_logout_at = ? WHERE id = ?').run([Date.now(), req.user.userId]);
  res.json({ ok: true });
});

// ── Items ─────────────────────────────────────────────────────────────────────
app.get('/api/items', verifyToken, (req, res) => {
  const rows = db.prepare('SELECT * FROM items WHERE user_id = ? ORDER BY modified_at DESC').all(req.user.userId);
  res.json(rows.map(itemToJSON));
});

app.post('/api/items', verifyToken, (req, res) => {
  const { userId } = req.user;
  const {
    name, description = '', category = '', location = '',
    quantity = 1, unit = 'pcs', value = 0,
    brand = '', model = '', serial = '',
    condition = 'good', notes = '', tags = [], image_data = null
  } = req.body || {};

  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  const qr_token = crypto.randomBytes(12).toString('hex');
  const now = Math.floor(Date.now() / 1000);

  db.prepare(`
    INSERT INTO items
      (user_id, name, description, category, location, quantity, unit, value,
       brand, model, serial, condition, notes, tags, qr_token, image_data, created_at, modified_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run([
    userId, name.trim(), description, category, location,
    quantity, unit, value, brand, model, serial, condition,
    notes, JSON.stringify(tags), qr_token, image_data, now, now
  ]);

  const item = db.prepare('SELECT * FROM items WHERE qr_token = ?').get(qr_token);
  res.status(201).json(itemToJSON(item));
});

app.get('/api/items/:id', verifyToken, (req, res) => {
  const item = db.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?').get([Number(req.params.id), req.user.userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(itemToJSON(item));
});

app.put('/api/items/:id', verifyToken, (req, res) => {
  const { userId } = req.user;
  const itemId = Number(req.params.id);
  const existing = db.prepare('SELECT id FROM items WHERE id = ? AND user_id = ?').get([itemId, userId]);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const {
    name, description = '', category = '', location = '',
    quantity = 1, unit = 'pcs', value = 0,
    brand = '', model = '', serial = '',
    condition = 'good', notes = '', tags = [], image_data = null
  } = req.body || {};

  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    UPDATE items SET
      name=?, description=?, category=?, location=?,
      quantity=?, unit=?, value=?,
      brand=?, model=?, serial=?,
      condition=?, notes=?, tags=?, image_data=?, modified_at=?
    WHERE id=? AND user_id=?
  `).run([
    name.trim(), description, category, location,
    quantity, unit, value, brand, model, serial,
    condition, notes, JSON.stringify(tags), image_data,
    now, itemId, userId
  ]);

  res.json(itemToJSON(db.prepare('SELECT * FROM items WHERE id = ?').get(itemId)));
});

app.delete('/api/items/:id', verifyToken, (req, res) => {
  db.prepare('DELETE FROM items WHERE id = ? AND user_id = ?').run([Number(req.params.id), req.user.userId]);
  res.json({ ok: true });
});

// ── QR code generation ────────────────────────────────────────────────────────
app.get('/api/items/:id/qr', verifyToken, async (req, res) => {
  const item = db.prepare('SELECT qr_token FROM items WHERE id = ? AND user_id = ?')
    .get([Number(req.params.id), req.user.userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host  = req.headers['x-forwarded-host']  || req.get('host');
  const url   = `${proto}://${host}/i/${item.qr_token}`;

  try {
    const svg = await QRCode.toString(url, { type: 'svg', margin: 2, width: 256,
      color: { dark: '#22d45a', light: '#080c09' } });
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send(svg);
  } catch {
    res.status(500).json({ error: 'QR generation failed' });
  }
});

// ── Public item page (no auth — for QR scan) ──────────────────────────────────
app.get('/i/:token', (req, res) => {
  const item = db.prepare(`
    SELECT i.*, u.email AS owner_email
    FROM items i JOIN users u ON u.id = i.user_id
    WHERE i.qr_token = ?
  `).get(req.params.token);

  if (!item) return res.status(404).send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Not Found — CACHE</title>
    <style>body{background:#080c09;color:#b4e8b0;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}h1{font-size:18px;letter-spacing:2px}</style>
    </head><body><div><h1>▌▌ CACHE</h1><p>Item not found.</p></div></body></html>
  `);

  const tags = JSON.parse(item.tags || '[]');
  const condColor = { new: '#22d45a', good: '#22d45a', fair: '#d4a020', poor: '#d44020' }[item.condition] || '#b4e8b0';
  const fmt = (n) => n ? `$${Number(n).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '—';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escHtml(item.name)} — CACHE</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c09;color:#b4e8b0;font-family:'Share Tech Mono',monospace;min-height:100vh;padding:0}
.header{background:#050807;border-bottom:2px solid #22d45a;padding:14px 20px;display:flex;align-items:center;gap:10px}
.logo{font-size:20px;letter-spacing:3px;color:#22d45a;font-weight:bold}
.logo-sub{font-size:10px;color:#4a7050;letter-spacing:2px}
.card{background:#0e1510;border:1px solid #1a3020;border-left:4px solid #22d45a;margin:20px;padding:20px;border-radius:2px}
.item-name{font-size:22px;letter-spacing:1px;margin-bottom:4px;color:#e0f8dc}
.item-brand{font-size:12px;color:#4a7050;margin-bottom:16px;letter-spacing:1px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
.field{background:#080c09;border:1px solid #1a3020;padding:10px 12px;border-radius:2px}
.field-label{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:#4a7050;margin-bottom:4px}
.field-val{font-size:14px;color:#b4e8b0}
.cond{color:${condColor}}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}
.tag{background:#0a2010;border:1px solid #1a3020;color:#22d45a;font-size:10px;letter-spacing:1px;padding:3px 8px;border-radius:1px}
.desc{background:#080c09;border:1px solid #1a3020;padding:12px;margin-top:12px;font-size:13px;color:#7ab870;line-height:1.6;border-radius:2px}
.footer{text-align:center;padding:20px;font-size:10px;color:#2a4030;letter-spacing:2px}
.open-link{display:inline-block;margin-top:16px;background:#22d45a;color:#080c09;padding:10px 24px;text-decoration:none;font-size:12px;letter-spacing:2px}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="logo">▌▌ CACHE</div>
    <div class="logo-sub">INVENTORY SYSTEM</div>
  </div>
</div>
<div class="card">
  <div class="item-name">${escHtml(item.name)}</div>
  <div class="item-brand">${[item.brand, item.model].filter(Boolean).map(escHtml).join(' / ') || 'No brand/model'}</div>
  <div class="row">
    <div class="field"><div class="field-label">Category</div><div class="field-val">${escHtml(item.category) || '—'}</div></div>
    <div class="field"><div class="field-label">Condition</div><div class="field-val cond">${escHtml(item.condition.toUpperCase())}</div></div>
    <div class="field"><div class="field-label">Location</div><div class="field-val">${escHtml(item.location) || '—'}</div></div>
    <div class="field"><div class="field-label">Quantity</div><div class="field-val">${item.quantity} ${escHtml(item.unit)}</div></div>
    <div class="field"><div class="field-label">Est. Value</div><div class="field-val">${fmt(item.value)}</div></div>
    ${item.serial ? `<div class="field"><div class="field-label">Serial</div><div class="field-val">${escHtml(item.serial)}</div></div>` : ''}
  </div>
  ${item.description ? `<div class="desc">${escHtml(item.description)}</div>` : ''}
  ${tags.length ? `<div class="tags">${tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join('')}</div>` : ''}
  <div style="text-align:center"><a class="open-link" href="/">OPEN IN CACHE →</a></div>
</div>
<div class="footer">CACHE // INVENTORY SYSTEM</div>
</body>
</html>`);
});

// ── Locations ─────────────────────────────────────────────────────────────────
app.get('/api/locations', verifyToken, (req, res) => {
  const rows = db.prepare('SELECT id, name FROM locations WHERE user_id = ? ORDER BY name').all(req.user.userId);
  res.json(rows);
});

app.post('/api/locations', verifyToken, (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    db.prepare('INSERT INTO locations (user_id, name) VALUES (?, ?)').run([req.user.userId, name.trim()]);
    const row = db.prepare('SELECT id, name FROM locations WHERE user_id = ? AND name = ?').get([req.user.userId, name.trim()]);
    res.status(201).json(row);
  } catch {
    res.status(409).json({ error: 'Location already exists' });
  }
});

app.delete('/api/locations/:id', verifyToken, (req, res) => {
  db.prepare('DELETE FROM locations WHERE id = ? AND user_id = ?').run([Number(req.params.id), req.user.userId]);
  res.json({ ok: true });
});

// ── Account ───────────────────────────────────────────────────────────────────
app.post('/api/account/password', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
  const match = await bcrypt.compare(currentPassword, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run([hash, userId]);
  res.json({ ok: true });
});

app.delete('/api/account', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const { password } = req.body || {};
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Password is incorrect' });

  db.prepare('DELETE FROM items WHERE user_id = ?').run([userId]);
  db.prepare('DELETE FROM users WHERE id = ?').run([userId]);
  res.json({ ok: true });
});

// ── Export / Import ───────────────────────────────────────────────────────────
app.get('/api/export', verifyToken, (req, res) => {
  const items = db.prepare('SELECT * FROM items WHERE user_id = ?').all(req.user.userId).map(itemToJSON);
  res.setHeader('Content-Disposition', 'attachment; filename="cache-export.json"');
  res.json({ version: 1, exported: new Date().toISOString(), items });
});

app.post('/api/import', verifyToken, (req, res) => {
  const { items = [] } = req.body || {};
  const { userId } = req.user;
  const now = Math.floor(Date.now() / 1000);
  let count = 0;

  for (const item of items) {
    if (!item.name) continue;
    try {
      db.prepare(`
        INSERT INTO items
          (user_id, name, description, category, location, quantity, unit, value,
           brand, model, serial, condition, notes, tags, qr_token, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run([
        userId, item.name, item.description||'', item.category||'', item.location||'',
        item.quantity||1, item.unit||'pcs', item.value||0,
        item.brand||'', item.model||'', item.serial||'',
        item.condition||'good', item.notes||'',
        JSON.stringify(Array.isArray(item.tags) ? item.tags : []),
        crypto.randomBytes(12).toString('hex'),
        item.created_at || now, now
      ]);
      count++;
    } catch {}
  }

  res.json({ ok: true, imported: count });
});

app.listen(PORT, () => {
  console.log(`CACHE running → http://localhost:${PORT}`);
});
