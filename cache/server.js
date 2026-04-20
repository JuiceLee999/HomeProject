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
const { GoogleGenerativeAI } = require('@google/generative-ai');

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

  CREATE TABLE IF NOT EXISTS lists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    qr_token    TEXT UNIQUE NOT NULL,
    created_at  INTEGER DEFAULT (strftime('%s','now')),
    modified_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS list_shares (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id        INTEGER NOT NULL,
    owner_id       INTEGER NOT NULL,
    shared_with_id INTEGER NOT NULL,
    created_at     INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(list_id, shared_with_id),
    FOREIGN KEY (list_id)        REFERENCES lists(id),
    FOREIGN KEY (owner_id)       REFERENCES users(id),
    FOREIGN KEY (shared_with_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS list_items (
    list_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    PRIMARY KEY (list_id, item_id),
    FOREIGN KEY (list_id) REFERENCES lists(id),
    FOREIGN KEY (item_id) REFERENCES items(id)
  );

  CREATE TABLE IF NOT EXISTS categories (
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

// ── AI item analysis ──────────────────────────────────────────────────────────
app.post('/api/ai/analyze-item', verifyToken, async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'AI not configured on this server' });

  const { image_data } = req.body;
  if (!image_data) return res.status(400).json({ error: 'No image provided' });

  const base64 = image_data.replace(/^data:image\/\w+;base64,/, '');
  const mimeType = image_data.startsWith('data:image/png') ? 'image/png' : 'image/jpeg';

  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

  const prompt = `You are analyzing an image of a physical item for an inventory management system.
Extract the following details and respond with ONLY valid JSON (no markdown, no code fences, no explanation):
{
  "name": "short descriptive item name",
  "brand": "brand/manufacturer or empty string",
  "model": "model number/name or empty string",
  "category": "one of: Automotive, Electronics, Tools, Clothing, Furniture, Kitchen, Sports, Books, Toys, Office, Other",
  "condition": "one of: new, good, fair, poor",
  "description": "1-2 sentence description of what this item is",
  "quantity": 1,
  "unit": "one of: pcs, boxes, bags, pairs, sets, rolls, ft, lbs, oz, gal, qt",
  "value": 0,
  "tags": ["tag1", "tag2"]
}
Be concise. If unsure about a field, use empty string or 0. Estimate value in USD if possible.`;

  try {
    const result = await model.generateContent([
      { inlineData: { data: base64, mimeType } },
      prompt
    ]);
    const text = result.response.text().trim();
    const cleaned = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '').trim();
    const json = JSON.parse(cleaned);
    res.json(json);
  } catch (e) {
    res.status(500).json({ error: 'AI analysis failed: ' + e.message });
  }
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

// ── Lists ─────────────────────────────────────────────────────────────────────
function listWithItems(list) {
  const item_ids = db.prepare('SELECT item_id FROM list_items WHERE list_id = ?')
    .all(list.id).map(r => r.item_id);
  return { ...list, item_ids };
}

app.get('/api/lists', verifyToken, (req, res) => {
  const { userId } = req.user;

  // Own lists — include who they're shared with
  const ownRows = db.prepare('SELECT * FROM lists WHERE user_id = ? ORDER BY modified_at DESC').all(userId);
  const ownLists = ownRows.map(list => {
    const item_ids = db.prepare('SELECT item_id FROM list_items WHERE list_id = ?').all(list.id).map(r => r.item_id);
    const shared_with = db.prepare(
      `SELECT ls.shared_with_id as id, u.email FROM list_shares ls
       JOIN users u ON u.id = ls.shared_with_id WHERE ls.list_id = ?`
    ).all(list.id);
    return { ...list, item_ids, is_shared: false, shared_with };
  });

  // Lists shared with this user — include full item preview data
  const sharedRows = db.prepare(
    `SELECT l.*, u.email as owner_email FROM list_shares ls
     JOIN lists l ON l.id = ls.list_id
     JOIN users u ON u.id = l.user_id
     WHERE ls.shared_with_id = ? ORDER BY l.modified_at DESC`
  ).all(userId);
  const sharedLists = sharedRows.map(list => {
    const item_ids = db.prepare('SELECT item_id FROM list_items WHERE list_id = ?').all(list.id).map(r => r.item_id);
    const shared_items = item_ids.length
      ? db.prepare(`SELECT name, category, location, condition, quantity, unit FROM items WHERE id IN (${item_ids.map(() => '?').join(',')})`).all(item_ids)
      : [];
    return { ...list, item_ids, is_shared: true, shared_with: [], shared_items };
  });

  res.json([...ownLists, ...sharedLists]);
});

app.post('/api/lists', verifyToken, (req, res) => {
  const { name, description = '', item_ids = [] } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  const qr_token = crypto.randomBytes(12).toString('hex');
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`INSERT INTO lists (user_id, name, description, qr_token, created_at, modified_at)
              VALUES (?, ?, ?, ?, ?, ?)`).run([req.user.userId, name.trim(), description, qr_token, now, now]);
  const list = db.prepare('SELECT * FROM lists WHERE qr_token = ?').get(qr_token);
  for (const id of item_ids) {
    try { db.prepare('INSERT INTO list_items (list_id, item_id) VALUES (?, ?)').run([list.id, id]); } catch {}
  }
  res.status(201).json(listWithItems(list));
});

app.put('/api/lists/:id', verifyToken, (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!db.prepare('SELECT id FROM lists WHERE id = ? AND user_id = ?').get([listId, userId]))
    return res.status(404).json({ error: 'Not found' });
  const { name, description = '', item_ids = [] } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  const now = Math.floor(Date.now() / 1000);
  db.prepare('UPDATE lists SET name=?, description=?, modified_at=? WHERE id=?').run([name.trim(), description, now, listId]);
  db.prepare('DELETE FROM list_items WHERE list_id = ?').run([listId]);
  for (const id of item_ids) {
    try { db.prepare('INSERT INTO list_items (list_id, item_id) VALUES (?, ?)').run([listId, id]); } catch {}
  }
  res.json(listWithItems(db.prepare('SELECT * FROM lists WHERE id = ?').get(listId)));
});

app.delete('/api/lists/:id', verifyToken, (req, res) => {
  const listId = Number(req.params.id);
  db.prepare('DELETE FROM list_shares WHERE list_id = ?').run([listId]);
  db.prepare('DELETE FROM list_items WHERE list_id = ?').run([listId]);
  db.prepare('DELETE FROM lists WHERE id = ? AND user_id = ?').run([listId, req.user.userId]);
  res.json({ ok: true });
});

// Share a list with another user (owner only)
app.post('/api/lists/:id/shares', verifyToken, (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!db.prepare('SELECT id FROM lists WHERE id = ? AND user_id = ?').get([listId, userId]))
    return res.status(404).json({ error: 'Not found' });
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });
  const target = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!target) return res.status(404).json({ error: 'No account found with that email' });
  if (target.id === userId) return res.status(400).json({ error: 'Cannot share with yourself' });
  try {
    db.prepare('INSERT INTO list_shares (list_id, owner_id, shared_with_id) VALUES (?, ?, ?)').run([listId, userId, target.id]);
    res.json({ id: target.id, email: target.email });
  } catch { res.status(409).json({ error: 'Already shared with this user' }); }
});

// Revoke share (owner removes a user's access)
app.delete('/api/lists/:id/shares/:sharedWithId', verifyToken, (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!db.prepare('SELECT id FROM lists WHERE id = ? AND user_id = ?').get([listId, userId]))
    return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM list_shares WHERE list_id = ? AND shared_with_id = ?').run([listId, Number(req.params.sharedWithId)]);
  res.json({ ok: true });
});

// Leave a shared list (recipient removes it from their view)
app.delete('/api/shared-lists/:listId', verifyToken, (req, res) => {
  db.prepare('DELETE FROM list_shares WHERE list_id = ? AND shared_with_id = ?').run([Number(req.params.listId), req.user.userId]);
  res.json({ ok: true });
});

app.get('/api/lists/:id/qr', verifyToken, async (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  let list = db.prepare('SELECT qr_token FROM lists WHERE id = ? AND user_id = ?').get([listId, userId]);
  if (!list) {
    // Also allow users the list is shared with
    const row = db.prepare(
      `SELECT l.qr_token FROM list_shares ls JOIN lists l ON l.id = ls.list_id
       WHERE ls.list_id = ? AND ls.shared_with_id = ?`
    ).get([listId, userId]);
    list = row || null;
  }
  if (!list) return res.status(404).json({ error: 'Not found' });
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host  = req.headers['x-forwarded-host']  || req.get('host');
  try {
    const svg = await QRCode.toString(`${proto}://${host}/l/${list.qr_token}`,
      { type: 'svg', margin: 2, width: 256, color: { dark: '#22d45a', light: '#080c09' } });
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send(svg);
  } catch { res.status(500).json({ error: 'QR generation failed' }); }
});

// ── Public list page ──────────────────────────────────────────────────────────
app.get('/l/:token', (req, res) => {
  const list = db.prepare('SELECT * FROM lists WHERE qr_token = ?').get(req.params.token);
  if (!list) return res.status(404).send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Not Found — CACHE</title>
    <style>body{background:#080c09;color:#b4e8b0;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}</style>
    </head><body><div><h1 style="font-size:18px;letter-spacing:2px">▌▌ CACHE</h1><p>List not found.</p></div></body></html>`);

  const itemIds = db.prepare('SELECT item_id FROM list_items WHERE list_id = ?').all(list.id).map(r => r.item_id);
  const listItems = itemIds.length
    ? db.prepare(`SELECT * FROM items WHERE id IN (${itemIds.map(() => '?').join(',')})`).all(itemIds)
    : [];
  const condColor = { new: '#22d45a', good: '#22d45a', fair: '#d4a020', poor: '#d44020' };

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escHtml(list.name)} — CACHE</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c09;color:#b4e8b0;font-family:'Share Tech Mono',monospace;min-height:100vh}
.header{background:#050807;border-bottom:2px solid #22d45a;padding:14px 20px;display:flex;align-items:center;gap:10px}
.logo{font-size:20px;letter-spacing:3px;color:#22d45a;font-weight:bold}
.logo-sub{font-size:10px;color:#4a7050;letter-spacing:2px}
.list-head{padding:20px;border-bottom:1px solid #1a3020}
.list-name{font-size:22px;letter-spacing:1px;color:#e0f8dc;margin-bottom:4px}
.list-desc{font-size:12px;color:#4a7050;letter-spacing:1px}
.list-meta{font-size:10px;color:#2a4030;margin-top:6px;letter-spacing:1px}
.items{padding:16px;display:flex;flex-direction:column;gap:10px}
.item-row{background:#0e1510;border:1px solid #1a3020;border-left:3px solid #22d45a;padding:14px 16px;text-decoration:none;display:block;transition:border-color 0.15s}
.item-row:hover{border-left-color:#b4e8b0}
.item-row[data-cond="fair"]{border-left-color:#d4a020}
.item-row[data-cond="poor"]{border-left-color:#d44020}
.row-top{display:flex;align-items:flex-start;gap:8px;margin-bottom:6px}
.row-name{flex:1;font-size:15px;color:#e0f8dc;letter-spacing:0.5px}
.row-cond{font-size:9px;letter-spacing:1px;padding:2px 6px;border:1px solid;text-transform:uppercase}
.row-meta{display:flex;gap:12px;font-size:11px;color:#4a7050;flex-wrap:wrap}
.empty{padding:40px;text-align:center;color:#2a4030;font-size:11px;letter-spacing:2px}
.open-link{display:inline-block;margin:16px 20px;background:#22d45a;color:#080c09;padding:10px 24px;text-decoration:none;font-size:11px;letter-spacing:2px}
.footer{text-align:center;padding:20px;font-size:10px;color:#2a4030;letter-spacing:2px}
</style>
</head>
<body>
<div class="header">
  <div><div class="logo">▌▌ CACHE</div><div class="logo-sub">INVENTORY SYSTEM</div></div>
</div>
<div class="list-head">
  <div class="list-name">${escHtml(list.name)}</div>
  ${list.description ? `<div class="list-desc">${escHtml(list.description)}</div>` : ''}
  <div class="list-meta">${listItems.length} ITEM${listItems.length !== 1 ? 'S' : ''}</div>
</div>
<div class="items">
${listItems.map(item => {
  const cc = condColor[item.condition] || '#b4e8b0';
  return `<a class="item-row" href="/i/${escHtml(item.qr_token)}" data-cond="${escHtml(item.condition)}">
    <div class="row-top">
      <span class="row-name">${escHtml(item.name)}</span>
      <span class="row-cond" style="border-color:${cc};color:${cc}">${escHtml(item.condition.toUpperCase())}</span>
    </div>
    <div class="row-meta">
      ${item.category ? `<span>${escHtml(item.category)}</span>` : ''}
      ${item.location ? `<span>⊹ ${escHtml(item.location)}</span>` : ''}
      <span>${item.quantity} ${escHtml(item.unit)}</span>
    </div>
  </a>`;
}).join('') || '<div class="empty">NO ITEMS IN THIS LIST</div>'}
</div>
<a class="open-link" href="/">OPEN IN CACHE →</a>
<div class="footer">CACHE // INVENTORY SYSTEM</div>
</body>
</html>`);
});

// ── Categories ────────────────────────────────────────────────────────────────
app.get('/api/categories', verifyToken, (req, res) => {
  const rows = db.prepare('SELECT id, name FROM categories WHERE user_id = ? ORDER BY name').all(req.user.userId);
  res.json(rows);
});

app.post('/api/categories', verifyToken, (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    db.prepare('INSERT INTO categories (user_id, name) VALUES (?, ?)').run([req.user.userId, name.trim()]);
    const row = db.prepare('SELECT id, name FROM categories WHERE user_id = ? AND name = ?').get([req.user.userId, name.trim()]);
    res.status(201).json(row);
  } catch {
    res.status(409).json({ error: 'Category already exists' });
  }
});

app.delete('/api/categories/:id', verifyToken, (req, res) => {
  db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run([Number(req.params.id), req.user.userId]);
  res.json({ ok: true });
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
