const express = require('express');
const { Database } = require('node-sqlite3-wasm');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_DIR = path.join(__dirname, 'db');
const DB_PATH = path.join(DB_DIR, 'homeworks.db');

fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);

// ── Schema ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id INTEGER PRIMARY KEY,
    value   TEXT NOT NULL DEFAULT '{"projects":[],"customCats":[],"contractors":[],"properties":[]}',
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS project_shares (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL,
    owner_id       INTEGER NOT NULL,
    shared_with_id INTEGER NOT NULL,
    permission     TEXT NOT NULL CHECK(permission IN ('view','edit')),
    UNIQUE(project_id, shared_with_id),
    FOREIGN KEY (owner_id)       REFERENCES users(id),
    FOREIGN KEY (shared_with_id) REFERENCES users(id)
  );
`);

// ── node-sqlite3-wasm quirk ───────────────────────────────────────────────────
// prepare().run/get/all() silently binds NULL when multiple params are passed
// as individual arguments. Always pass params as an array: .run([a, b]).

// ── Schema migrations ─────────────────────────────────────────────────────────
try { db.exec('ALTER TABLE users ADD COLUMN last_logout_at INTEGER DEFAULT 0'); } catch {}


// ── JWT secret (auto-generated, persisted in DB) ─────────────────────────────
let JWT_SECRET;
const secretRow = db.prepare('SELECT value FROM store WHERE key = ?').get('jwt_secret');
if (secretRow) {
  JWT_SECRET = secretRow.value;
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO store (key, value) VALUES (?, ?)').run([`jwt_secret`, JWT_SECRET]);
}

// ── Legacy data migration ────────────────────────────────────────────────────
// If the old single-blob row exists, the first user to register claims it.
const legacyRow = db.prepare("SELECT value FROM store WHERE key = 'homeworks'").get();
let legacyData = legacyRow ? legacyRow.value : null;

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],
      styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:     ["https://fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:", "blob:"],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      baseUri:     ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters — 20 attempts per 15 min on auth endpoints
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
    // Reject tokens issued before the user's last logout
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

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 10);
  db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run([email, hash]);
  const userRow = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const userId = userRow.id;

  // First user claims legacy data
  const initialData = legacyData || '{"projects":[],"customCats":[],"contractors":[],"properties":[]}';
  db.prepare('INSERT INTO user_data (user_id, value) VALUES (?, ?)').run([userId, initialData]);
  if (legacyData) {
    db.prepare("DELETE FROM store WHERE key = 'homeworks'").run();
    legacyData = null;
  }

  const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

app.post('/api/logout', verifyToken, (req, res) => {
  db.prepare('UPDATE users SET last_logout_at = ? WHERE id = ?').run([Date.now(), req.user.userId]);
  res.json({ ok: true });
});

// ── Data routes ──────────────────────────────────────────────────────────────
app.get('/api/data', verifyToken, (req, res) => {
  const { userId } = req.user;

  const row = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(userId);
  const ownData = row ? JSON.parse(row.value) : { projects: [], customCats: [], contractors: [], properties: [] };

  // Load projects shared with this user
  const shares = db.prepare(`
    SELECT ps.project_id, ps.permission, ps.owner_id, u.email AS owner_email
    FROM project_shares ps
    JOIN users u ON u.id = ps.owner_id
    WHERE ps.shared_with_id = ?
  `).all(userId);

  const sharedProjects = [];
  for (const share of shares) {
    const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(share.owner_id);
    if (!ownerRow) continue;
    const ownerData = JSON.parse(ownerRow.value);
    const project = (ownerData.projects || []).find(p => p.id === share.project_id);
    if (project) {
      sharedProjects.push({ ...project, _sharedBy: share.owner_email, _permission: share.permission, _ownerId: share.owner_id });
    }
  }

  res.json({ ...ownData, sharedProjects });
});

app.put('/api/data', verifyToken, (req, res) => {
  const { userId } = req.user;
  const { projects = [], customCats = [], contractors = [], properties = [] } = req.body || {};
  const value = JSON.stringify({ projects, customCats, contractors, properties });
  db.prepare('INSERT OR REPLACE INTO user_data (user_id, value) VALUES (?, ?)').run([userId, value]);
  res.json({ ok: true });
});

// Save a single shared project back to its owner's blob
app.put('/api/projects/:projectId', verifyToken, (req, res) => {
  const { userId } = req.user;
  const projectId = Number(req.params.projectId);
  const updatedProject = req.body;

  const share = db.prepare(`
    SELECT owner_id FROM project_shares
    WHERE project_id = ? AND shared_with_id = ? AND permission = 'edit'
  `).get([projectId, userId]);
  if (!share) return res.status(403).json({ error: 'No edit permission on this project' });

  const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(share.owner_id);
  if (!ownerRow) return res.status(404).json({ error: 'Owner data not found' });

  const ownerData = JSON.parse(ownerRow.value);
  const idx = (ownerData.projects || []).findIndex(p => p.id === projectId);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });

  // Strip client-side share flags before saving
  const { _sharedBy, _permission, _ownerId, ...cleanProject } = updatedProject;
  ownerData.projects[idx] = cleanProject;
  db.prepare('INSERT OR REPLACE INTO user_data (user_id, value) VALUES (?, ?)').run([share.owner_id, JSON.stringify(ownerData)]);
  res.json({ ok: true });
});

// ── Sharing routes ────────────────────────────────────────────────────────────
app.get('/api/shares/:projectId', verifyToken, (req, res) => {
  const { userId } = req.user;
  const projectId = Number(req.params.projectId);

  // Verify ownership
  const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(userId);
  if (!ownerRow) return res.status(404).json({ error: 'Not found' });
  const ownerData = JSON.parse(ownerRow.value);
  const owned = (ownerData.projects || []).some(p => p.id === projectId);
  if (!owned) return res.status(403).json({ error: 'Not your project' });

  const shares = db.prepare(`
    SELECT u.email, ps.permission
    FROM project_shares ps
    JOIN users u ON u.id = ps.shared_with_id
    WHERE ps.project_id = ? AND ps.owner_id = ?
  `).all([projectId, userId]);

  res.json(shares);
});

app.post('/api/share', verifyToken, (req, res) => {
  const { userId, email: ownerEmail } = req.user;
  const { projectId, email, permission } = req.body || {};
  if (!projectId || !email || !['view', 'edit'].includes(permission))
    return res.status(400).json({ error: 'projectId, email, and permission (view|edit) required' });
  if (!isValidEmail(email))
    return res.status(400).json({ error: 'Valid email required' });
  if (email.toLowerCase() === ownerEmail.toLowerCase())
    return res.status(400).json({ error: "You can't share a project with yourself" });

  // Verify ownership
  const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(userId);
  if (!ownerRow) return res.status(404).json({ error: 'Not found' });
  const ownerData = JSON.parse(ownerRow.value);
  const owned = (ownerData.projects || []).some(p => p.id === Number(projectId));
  if (!owned) return res.status(403).json({ error: 'Not your project' });

  const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  // Generic message — avoids leaking whether an email is registered
  if (!target) return res.status(404).json({ error: 'No account found with that email' });

  db.prepare(`
    INSERT INTO project_shares (project_id, owner_id, shared_with_id, permission)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(project_id, shared_with_id) DO UPDATE SET permission = excluded.permission
  `).run([Number(projectId), userId, target.id, permission]);

  res.json({ ok: true });
});

app.delete('/api/share', verifyToken, (req, res) => {
  const { userId } = req.user;
  const { projectId, email } = req.body || {};
  if (!projectId || !email) return res.status(400).json({ error: 'projectId and email required' });

  const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!target) return res.status(404).json({ error: 'User not found' });

  db.prepare('DELETE FROM project_shares WHERE project_id = ? AND owner_id = ? AND shared_with_id = ?')
    .run([Number(projectId), userId, target.id]);

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Honey-Do running → http://localhost:${PORT}`);
});
