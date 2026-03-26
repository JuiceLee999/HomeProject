const express = require('express');
const { Database } = require('node-sqlite3-wasm');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const APP_URL = (process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
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

  CREATE TABLE IF NOT EXISTS pending_invites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    owner_id   INTEGER NOT NULL,
    email      TEXT NOT NULL COLLATE NOCASE,
    permission TEXT NOT NULL CHECK(permission IN ('view','edit')),
    token      TEXT UNIQUE NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(project_id, email),
    FOREIGN KEY (owner_id) REFERENCES users(id)
  );
`);

// ── JWT secret (auto-generated, persisted in DB) ─────────────────────────────
let JWT_SECRET;
const secretRow = db.prepare('SELECT value FROM store WHERE key = ?').get('jwt_secret');
if (secretRow) {
  JWT_SECRET = secretRow.value;
} else {
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  db.exec(`INSERT INTO store (key, value) VALUES ('jwt_secret', ${sqlStr(JWT_SECRET)})`);
}

// ── Legacy data migration ────────────────────────────────────────────────────
// If the old single-blob row exists, the first user to register claims it.
const legacyRow = db.prepare("SELECT value FROM store WHERE key = 'homeworks'").get();
let legacyData = legacyRow ? legacyRow.value : null;

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function isValidEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }
// node-sqlite3-wasm 0.8.x has a bug where prepare().run() with string params
// silently binds NULL. Use exec() + sqlStr() for all write operations instead.
function sqlStr(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }

// ── Email (optional — only active when SMTP_HOST env var is set) ─────────────
let mailer = null;
if (process.env.SMTP_HOST) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

async function sendInviteEmail(toEmail, inviteLink, ownerEmail, projectName) {
  if (!mailer) { console.log(`[invite] No SMTP configured. Link: ${inviteLink}`); return; }
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `HomeWorks <noreply@homeworks.app>`,
      to: toEmail,
      subject: `${ownerEmail} invited you to a project on HomeWorks`,
      text: `${ownerEmail} shared "${projectName}" with you on HomeWorks.\n\nCreate your account here:\n${inviteLink}`,
      html: `<p><strong>${ownerEmail}</strong> shared <em>${projectName}</em> with you on HomeWorks.</p>
             <p><a href="${inviteLink}" style="padding:10px 20px;background:#c8440a;color:#fff;text-decoration:none;border-radius:4px">Accept Invitation</a></p>
             <p style="color:#888;font-size:12px">Or copy: ${inviteLink}</p>`
    });
  } catch (e) { console.error('[invite] Email send failed:', e.message); }
}

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 10);
  db.exec(`INSERT INTO users (email, password_hash) VALUES (${sqlStr(email)}, ${sqlStr(hash)})`);
  const userRow = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  const userId = userRow.id;

  // First user claims legacy data
  const initialData = legacyData || '{"projects":[],"customCats":[],"contractors":[],"properties":[]}';
  db.exec(`INSERT INTO user_data (user_id, value) VALUES (${userId}, ${sqlStr(initialData)})`);
  if (legacyData) {
    db.exec("DELETE FROM store WHERE key = 'homeworks'");
    legacyData = null;
  }

  // Claim any pending invites for this email
  const pending = db.prepare('SELECT project_id, owner_id, permission FROM pending_invites WHERE email = ?').all(email);
  for (const inv of pending) {
    db.exec(`INSERT OR IGNORE INTO project_shares (project_id, owner_id, shared_with_id, permission) VALUES (${inv.project_id}, ${inv.owner_id}, ${userId}, ${sqlStr(inv.permission)})`);
  }
  if (pending.length) db.exec(`DELETE FROM pending_invites WHERE email = ${sqlStr(email)}`);

  const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email });
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
  db.exec(`INSERT OR REPLACE INTO user_data (user_id, value) VALUES (${userId}, ${sqlStr(value)})`);
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
  `).get(projectId, userId);
  if (!share) return res.status(403).json({ error: 'No edit permission on this project' });

  const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(share.owner_id);
  if (!ownerRow) return res.status(404).json({ error: 'Owner data not found' });

  const ownerData = JSON.parse(ownerRow.value);
  const idx = (ownerData.projects || []).findIndex(p => p.id === projectId);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });

  // Strip client-side share flags before saving
  const { _sharedBy, _permission, _ownerId, ...cleanProject } = updatedProject;
  ownerData.projects[idx] = cleanProject;
  db.exec(`INSERT OR REPLACE INTO user_data (user_id, value) VALUES (${share.owner_id}, ${sqlStr(JSON.stringify(ownerData))})`);
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
    SELECT u.email, ps.permission, 'active' AS status
    FROM project_shares ps
    JOIN users u ON u.id = ps.shared_with_id
    WHERE ps.project_id = ? AND ps.owner_id = ?
  `).all(projectId, userId);

  const pending = db.prepare(`
    SELECT email, permission, 'pending' AS status
    FROM pending_invites WHERE project_id = ? AND owner_id = ?
  `).all(projectId, userId);

  res.json([...shares, ...pending]);
});

app.post('/api/share', verifyToken, async (req, res) => {
  const { userId, email: ownerEmail } = req.user;
  const { projectId, email, permission } = req.body || {};
  if (!projectId || !email || !['view', 'edit'].includes(permission))
    return res.status(400).json({ error: 'projectId, email, and permission (view|edit) required' });
  if (email.toLowerCase() === ownerEmail.toLowerCase())
    return res.status(400).json({ error: "You can't share a project with yourself" });

  // Verify ownership
  const ownerRow = db.prepare('SELECT value FROM user_data WHERE user_id = ?').get(userId);
  if (!ownerRow) return res.status(404).json({ error: 'Not found' });
  const ownerData = JSON.parse(ownerRow.value);
  const project = (ownerData.projects || []).find(p => p.id === Number(projectId));
  if (!project) return res.status(403).json({ error: 'Not your project' });

  const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!target) {
    // No account yet — create pending invite and send email
    const token = crypto.randomBytes(24).toString('hex');
    db.exec(`INSERT INTO pending_invites (project_id, owner_id, email, permission, token) VALUES (${Number(projectId)}, ${userId}, ${sqlStr(email)}, ${sqlStr(permission)}, ${sqlStr(token)}) ON CONFLICT(project_id, email) DO UPDATE SET permission = excluded.permission, token = excluded.token`);
    const inviteLink = `${APP_URL}/invite/${token}`;
    await sendInviteEmail(email, inviteLink, ownerEmail, project.name);
    return res.json({ ok: true, pending: true, inviteLink });
  }

  db.exec(`INSERT INTO project_shares (project_id, owner_id, shared_with_id, permission) VALUES (${Number(projectId)}, ${userId}, ${target.id}, ${sqlStr(permission)}) ON CONFLICT(project_id, shared_with_id) DO UPDATE SET permission = excluded.permission`);
  res.json({ ok: true });
});

app.delete('/api/share', verifyToken, (req, res) => {
  const { userId } = req.user;
  const { projectId, email } = req.body || {};
  if (!projectId || !email) return res.status(400).json({ error: 'projectId and email required' });

  // Remove active share (if user exists)
  const target = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (target) {
    db.exec(`DELETE FROM project_shares WHERE project_id = ${Number(projectId)} AND owner_id = ${userId} AND shared_with_id = ${target.id}`);
  }
  // Remove pending invite (if any)
  db.exec(`DELETE FROM pending_invites WHERE project_id = ${Number(projectId)} AND owner_id = ${userId} AND email = ${sqlStr(email)}`);

  res.json({ ok: true });
});

// ── Invite link ───────────────────────────────────────────────────────────────
app.get('/invite/:token', (req, res) => {
  const invite = db.prepare('SELECT email FROM pending_invites WHERE token = ?').get(req.params.token);
  if (!invite) return res.redirect('/?invite_invalid=1');
  res.redirect(`/?invited_email=${encodeURIComponent(invite.email)}`);
});

app.listen(PORT, () => {
  console.log(`HomeWorks running → http://localhost:${PORT}`);
});
