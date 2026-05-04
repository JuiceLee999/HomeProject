const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const QRCode      = require('qrcode');
const Anthropic   = require('@anthropic-ai/sdk');
const PDFDocument = require('pdfkit');
const nodemailer  = require('nodemailer');
const db          = require('./db/index');

const app  = express();
const PORT = process.env.PORT || 3001;
let JWT_SECRET;

const mailer = nodemailer.createTransport({
  host:   process.env.EMAIL_HOST,
  port:   Number(process.env.EMAIL_PORT) || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth:   { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function itemToJSON(row) {
  if (!row) return null;
  return { ...row, tags: JSON.parse(row.tags || '[]') };
}

async function listWithItems(list) {
  const rows = await db.getAll('SELECT item_id FROM list_items WHERE list_id = $1', [list.id]);
  return { ...list, item_ids: rows.map(r => r.item_id) };
}

// Wraps async route handlers so Express 4 catches rejected promises.
const ar = fn => (req, res, next) => fn(req, res, next).catch(next);

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
app.use(express.json({ limit: '25mb' }));

const BASE = process.env.BASE_PATH || '/shit';
const router = express.Router();
router.use(express.static(path.join(__dirname, 'public')));

router.get('/lib/jsqr.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules', 'jsqr', 'dist', 'jsQR.js'));
});

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

const qrLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
});

const aiLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many AI analysis requests, please slow down.' }
});

const docUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Upload limit reached, please try again later.' }
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

// ── Auth helpers ──────────────────────────────────────────────────────────────
async function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    const userRow = await db.getOne('SELECT last_logout_at FROM users WHERE id = $1', [decoded.userId]);
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

function isStrongPassword(p) {
  if (!p) return false;
  if (p.length >= 12) return true;
  return p.length >= 8 && /[0-9!@#$%^&*()\-_=+[\]{};':",.<>?/\\|`~]/.test(p);
}

const VALID_CONDITIONS = new Set(['new', 'good', 'fair', 'poor']);

function requireJSON(req, res, next) {
  if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
  next();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
router.post('/api/register', authLimiter, requireJSON, ar(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be 12+ characters, or 8+ characters with at least one number or symbol' });

  const exists = await db.getOne('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 10);
  const userRow = await db.getOne(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
    [email.toLowerCase(), hash]
  );
  const token = jwt.sign({ userId: userRow.id, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: email.toLowerCase() });
}));

router.post('/api/login', authLimiter, requireJSON, ar(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await db.getOne(
    'SELECT id, email, password_hash FROM users WHERE LOWER(email) = LOWER($1)',
    [email]
  );
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
}));

router.post('/api/logout', verifyToken, requireJSON, ar(async (req, res) => {
  await db.query('UPDATE users SET last_logout_at = $1 WHERE id = $2', [Date.now(), req.user.userId]);
  res.json({ ok: true });
}));

router.post('/api/auth/forgot-password', resetLimiter, requireJSON, ar(async (req, res) => {
  const { email } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });

  const user = await db.getOne('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  if (user) {
    const rawToken  = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour

    await db.query('DELETE FROM password_resets WHERE user_id = $1', [user.id]);
    await db.query(
      'INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1,$2,$3)',
      [tokenHash, user.id, expiresAt]
    );

    const proto    = req.headers['x-forwarded-proto'] || req.protocol;
    const host     = req.headers['x-forwarded-host']  || req.get('host');
    const basePath = process.env.BASE_PATH || '';
    const resetUrl = `${proto}://${host}${basePath}?reset=${rawToken}`;

    await mailer.sendMail({
      from:    process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to:      email,
      subject: 'Password reset — SHIT Inventory',
      text:    `You requested a password reset.\n\nClick the link below to set a new password. This link expires in 1 hour.\n\n${resetUrl}\n\nIf you didn't request this, ignore this email.`,
      html:    `<p>You requested a password reset for your SHIT Inventory account.</p><p><a href="${resetUrl}">Reset your password →</a></p><p>This link expires in 1 hour. If you didn't request this, ignore this email.</p>`,
    }).catch(() => {}); // non-fatal — don't leak send failures
  }

  res.json({ ok: true }); // always succeed to prevent user enumeration
}));

router.post('/api/auth/reset-password', resetLimiter, requireJSON, ar(async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be 12+ characters, or 8+ characters with at least one number or symbol' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const row = await db.getOne('SELECT * FROM password_resets WHERE token_hash = $1', [tokenHash]);

  if (!row) return res.status(400).json({ error: 'Invalid or expired reset link' });
  if (Date.now() > row.expires_at) {
    await db.query('DELETE FROM password_resets WHERE token_hash = $1', [tokenHash]);
    return res.status(400).json({ error: 'Reset link has expired — please request a new one' });
  }

  const hash = await bcrypt.hash(password, 10);
  await db.query('UPDATE users SET password_hash = $1, last_logout_at = $2 WHERE id = $3', [hash, Date.now(), row.user_id]);
  await db.query('DELETE FROM password_resets WHERE token_hash = $1', [tokenHash]);

  const user = await db.getOne('SELECT id, email FROM users WHERE id = $1', [row.user_id]);
  const newToken = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token: newToken, email: user.email });
}));

// ── Items ─────────────────────────────────────────────────────────────────────
router.get('/api/items', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT * FROM items WHERE user_id = $1 ORDER BY modified_at DESC',
    [req.user.userId]
  );
  res.json(rows.map(itemToJSON));
}));

router.post('/api/items', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const {
    name, description = '', category = '', location = '',
    quantity = 1, unit = 'pcs', value = 0,
    brand = '', model = '', serial = '',
    condition = 'good', notes = '', tags = [], image_data = null,
    purchased_at = null
  } = req.body || {};

  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  const qty = Number(quantity);
  const val = Number(value);
  if (!Number.isFinite(qty) || qty < 0 || qty > 999999) return res.status(400).json({ error: 'Quantity must be between 0 and 999999' });
  if (!Number.isFinite(val) || val < 0 || val > 999999999) return res.status(400).json({ error: 'Value must be between 0 and 999999999' });
  if (!VALID_CONDITIONS.has(condition)) return res.status(400).json({ error: 'Condition must be one of: new, good, fair, poor' });

  const qr_token = crypto.randomBytes(12).toString('hex');
  const now = Math.floor(Date.now() / 1000);

  const item = await db.getOne(`
    INSERT INTO items
      (user_id, name, description, category, location, quantity, unit, value,
       brand, model, serial, condition, notes, tags, qr_token, image_data, purchased_at, created_at, modified_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
    RETURNING *
  `, [
    userId, name.trim(), description, category, location,
    qty, unit, val, brand, model, serial, condition,
    notes, JSON.stringify(tags), qr_token, image_data, purchased_at || null, now, now
  ]);

  res.status(201).json(itemToJSON(item));
}));

router.get('/api/items/:id', verifyToken, ar(async (req, res) => {
  const item = await db.getOne(
    'SELECT * FROM items WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(itemToJSON(item));
}));

router.put('/api/items/:id', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const itemId = Number(req.params.id);
  const existing = await db.getOne('SELECT id FROM items WHERE id = $1 AND user_id = $2', [itemId, userId]);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const {
    name, description = '', category = '', location = '',
    quantity = 1, unit = 'pcs', value = 0,
    brand = '', model = '', serial = '',
    condition = 'good', notes = '', tags = [], image_data = null,
    purchased_at = null
  } = req.body || {};

  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  const qty = Number(quantity);
  const val = Number(value);
  if (!Number.isFinite(qty) || qty < 0 || qty > 999999) return res.status(400).json({ error: 'Quantity must be between 0 and 999999' });
  if (!Number.isFinite(val) || val < 0 || val > 999999999) return res.status(400).json({ error: 'Value must be between 0 and 999999999' });
  if (!VALID_CONDITIONS.has(condition)) return res.status(400).json({ error: 'Condition must be one of: new, good, fair, poor' });

  const now = Math.floor(Date.now() / 1000);
  const item = await db.getOne(`
    UPDATE items SET
      name=$1, description=$2, category=$3, location=$4,
      quantity=$5, unit=$6, value=$7,
      brand=$8, model=$9, serial=$10,
      condition=$11, notes=$12, tags=$13, image_data=$14, purchased_at=$15, modified_at=$16
    WHERE id=$17 AND user_id=$18
    RETURNING *
  `, [
    name.trim(), description, category, location,
    qty, unit, val, brand, model, serial,
    condition, notes, JSON.stringify(tags), image_data, purchased_at || null,
    now, itemId, userId
  ]);

  res.json(itemToJSON(item));
}));

router.delete('/api/items/:id', verifyToken, ar(async (req, res) => {
  await db.query(
    'DELETE FROM items WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  res.json({ ok: true });
}));

// ── Checkout / check-in ───────────────────────────────────────────────────────
router.post('/api/items/:id/checkout', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const itemId = Number(req.params.id);
  const item = await db.getOne('SELECT * FROM items WHERE id = $1 AND user_id = $2', [itemId, userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });

  const { borrower, destination = '', checked_out_date = null, due_back = null, notes = '', quantity = 1 } = req.body || {};
  if (!borrower || !borrower.trim()) return res.status(400).json({ error: 'Borrower name is required' });

  const qty = Math.max(1, Math.round(Number(quantity) || 1));
  const available = Number(item.quantity) - Number(item.qty_checked_out || 0);
  if (qty > available) return res.status(400).json({ error: `Only ${available} available to check out` });

  const now   = Math.floor(Date.now() / 1000);
  const coTs  = checked_out_date ? Math.floor(new Date(checked_out_date).getTime() / 1000) : now;
  const dueTs = due_back ? Math.floor(new Date(due_back).getTime() / 1000) : null;
  const newQtyOut = Number(item.qty_checked_out || 0) + qty;

  const updated = await db.getOne(`
    UPDATE items SET checked_out_to=$1, checked_out_at=$2, due_back=$3, checkout_destination=$4,
      qty_checked_out=$5, modified_at=$6
    WHERE id=$7 RETURNING *
  `, [borrower.trim(), coTs, dueTs, destination.trim(), newQtyOut, now, itemId]);

  await db.query(
    'INSERT INTO checkouts (item_id, user_id, borrower, destination, checked_out, due_back, notes, quantity) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [itemId, userId, borrower.trim(), destination.trim(), coTs, dueTs, notes, qty]
  );

  res.json(itemToJSON(updated));
}));

router.post('/api/items/:id/checkin', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const itemId = Number(req.params.id);
  const item = await db.getOne('SELECT * FROM items WHERE id = $1 AND user_id = $2', [itemId, userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });
  if (!(Number(item.qty_checked_out) > 0) && !item.checked_out_to) return res.status(409).json({ error: 'Item is not checked out' });

  const now = Math.floor(Date.now() / 1000);
  const { checkout_id } = req.body || {};
  let updated;

  if (checkout_id) {
    const coRecord = await db.getOne(
      'SELECT * FROM checkouts WHERE id=$1 AND item_id=$2 AND checked_in IS NULL',
      [Number(checkout_id), itemId]
    );
    if (!coRecord) return res.status(404).json({ error: 'Checkout record not found' });
    await db.query('UPDATE checkouts SET checked_in=$1 WHERE id=$2', [now, coRecord.id]);
    const remaining = Math.max(0, Number(item.qty_checked_out) - Number(coRecord.quantity || 1));
    if (remaining === 0) {
      updated = await db.getOne(`
        UPDATE items SET checked_out_to=NULL, checked_out_at=NULL, due_back=NULL,
          checkout_destination=NULL, qty_checked_out=0, modified_at=$1 WHERE id=$2 RETURNING *
      `, [now, itemId]);
    } else {
      const nextActive = await db.getOne(
        'SELECT * FROM checkouts WHERE item_id=$1 AND checked_in IS NULL ORDER BY checked_out DESC LIMIT 1',
        [itemId]
      );
      updated = await db.getOne(`
        UPDATE items SET qty_checked_out=$1, checked_out_to=$2, checked_out_at=$3,
          due_back=$4, checkout_destination=$5, modified_at=$6 WHERE id=$7 RETURNING *
      `, [remaining, nextActive.borrower, nextActive.checked_out, nextActive.due_back, nextActive.destination, now, itemId]);
    }
  } else {
    await db.query('UPDATE checkouts SET checked_in=$1 WHERE item_id=$2 AND checked_in IS NULL', [now, itemId]);
    updated = await db.getOne(`
      UPDATE items SET checked_out_to=NULL, checked_out_at=NULL, due_back=NULL,
        checkout_destination=NULL, qty_checked_out=0, modified_at=$1 WHERE id=$2 RETURNING *
    `, [now, itemId]);
  }

  res.json(itemToJSON(updated));
}));

router.get('/api/items/:id/checkouts', verifyToken, ar(async (req, res) => {
  const { userId } = req.user;
  const itemId = Number(req.params.id);
  const item = await db.getOne('SELECT id FROM items WHERE id = $1 AND user_id = $2', [itemId, userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const history = await db.getAll(
    'SELECT * FROM checkouts WHERE item_id=$1 ORDER BY checked_out DESC',
    [itemId]
  );
  res.json(history);
}));

// ── Documents ─────────────────────────────────────────────────────────────────
router.get('/api/items/:id/documents', verifyToken, ar(async (req, res) => {
  const itemId = Number(req.params.id);
  const item = await db.getOne('SELECT id FROM items WHERE id = $1 AND user_id = $2', [itemId, req.user.userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const docs = await db.getAll(
    'SELECT id, filename, mime_type, size, thumb_data, created_at FROM documents WHERE item_id = $1 ORDER BY created_at DESC',
    [itemId]
  );
  res.json(docs);
}));

router.post('/api/items/:id/documents', verifyToken, docUploadLimiter, requireJSON, ar(async (req, res) => {
  const itemId = Number(req.params.id);
  const item = await db.getOne('SELECT id FROM items WHERE id = $1 AND user_id = $2', [itemId, req.user.userId]);
  if (!item) return res.status(404).json({ error: 'Not found' });

  const { filename, mime_type = 'application/octet-stream', data, thumb_data = null } = req.body || {};
  if (!filename || !data) return res.status(400).json({ error: 'filename and data required' });

  const size = Math.round(data.length * 0.75);
  const doc = await db.getOne(`
    INSERT INTO documents (item_id, user_id, filename, mime_type, size, data, thumb_data)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING id, filename, mime_type, size, thumb_data, created_at
  `, [itemId, req.user.userId, filename, mime_type, size, data, thumb_data]);

  res.status(201).json(doc);
}));

router.get('/api/documents/:id/download', verifyToken, ar(async (req, res) => {
  const doc = await db.getOne(
    'SELECT * FROM documents WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  if (!doc) return res.status(404).json({ error: 'Not found' });

  const buf = Buffer.from(doc.data, 'base64');
  res.setHeader('Content-Disposition', `attachment; filename="${doc.filename.replace(/"/g, '\\"')}"`);
  res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
  res.setHeader('Content-Length', buf.length);
  res.send(buf);
}));

router.delete('/api/documents/:id', verifyToken, ar(async (req, res) => {
  await db.query(
    'DELETE FROM documents WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  res.json({ ok: true });
}));

// ── AI item analysis ──────────────────────────────────────────────────────────
router.post('/api/ai/analyze-item', verifyToken, aiLimiter, requireJSON, async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'AI not configured on this server' });

  const { image_data } = req.body;
  if (!image_data) return res.status(400).json({ error: 'No image provided' });

  const base64    = image_data.replace(/^data:image\/\w+;base64,/, '');
  const mediaType = image_data.startsWith('data:image/png') ? 'image/png' : 'image/jpeg';
  const client    = new Anthropic({ apiKey });

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
    const message = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 512,
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } },
        { type: 'text', text: prompt }
      ]}]
    });
    const text    = message.content[0].text.trim();
    const cleaned = text.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '').trim();
    res.json(JSON.parse(cleaned));
  } catch (e) {
    console.error('AI analysis error:', e.message);
    res.status(500).json({ error: 'AI analysis failed. Please try again.' });
  }
});

// ── QR code generation ────────────────────────────────────────────────────────
router.get('/api/items/:id/qr', verifyToken, ar(async (req, res) => {
  const item = await db.getOne(
    'SELECT qr_token FROM items WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
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
}));

// ── Public item page (no auth — for QR scan) ──────────────────────────────────
router.get('/i/:token', qrLimiter, ar(async (req, res) => {
  const item = await db.getOne('SELECT * FROM items WHERE qr_token = $1', [req.params.token]);

  if (!item) return res.status(404).send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Not Found — SHIT</title>
    <style>body{background:#080c09;color:#b4e8b0;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}h1{font-size:18px;letter-spacing:2px}</style>
    </head><body><div><h1>▌▌ SHIT</h1><p>Item not found.</p></div></body></html>
  `);

  const tags      = JSON.parse(item.tags || '[]');
  const condColor = { new: '#22d45a', good: '#22d45a', fair: '#d4a020', poor: '#d44020' }[item.condition] || '#b4e8b0';
  const fmt       = (n) => n ? `$${Number(n).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '—';

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escHtml(item.name)} — SHIT</title>
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
    <div class="logo">▌▌ SHIT</div>
    <div class="logo-sub">SIMPLE HOME ITEM TRACKER</div>
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
  <div style="text-align:center"><a class="open-link" href="/">OPEN IN SHIT →</a></div>
</div>
<div class="footer">SHIT // SIMPLE HOME ITEM TRACKER &nbsp;&nbsp;·&nbsp;&nbsp; © 2025 JUICE LEE PRODUCTIONS</div>
</body>
</html>`);
}));

// ── Lists ─────────────────────────────────────────────────────────────────────
router.get('/api/lists', verifyToken, ar(async (req, res) => {
  const { userId } = req.user;

  const ownRows  = await db.getAll('SELECT * FROM lists WHERE user_id = $1 ORDER BY modified_at DESC', [userId]);
  const ownLists = await Promise.all(ownRows.map(async list => {
    const item_ids   = (await db.getAll('SELECT item_id FROM list_items WHERE list_id = $1', [list.id])).map(r => r.item_id);
    const shared_with = await db.getAll(
      `SELECT ls.shared_with_id AS id, u.email FROM list_shares ls
       JOIN users u ON u.id = ls.shared_with_id WHERE ls.list_id = $1`,
      [list.id]
    );
    return { ...list, item_ids, is_shared: false, shared_with };
  }));

  const sharedRows  = await db.getAll(
    `SELECT l.*, u.email AS owner_email FROM list_shares ls
     JOIN lists l ON l.id = ls.list_id
     JOIN users u ON u.id = l.user_id
     WHERE ls.shared_with_id = $1 ORDER BY l.modified_at DESC`,
    [userId]
  );
  const sharedLists = await Promise.all(sharedRows.map(async list => {
    const item_ids    = (await db.getAll('SELECT item_id FROM list_items WHERE list_id = $1', [list.id])).map(r => r.item_id);
    const shared_items = item_ids.length
      ? await db.getAll('SELECT name, category, location, condition, quantity, unit FROM items WHERE id = ANY($1)', [item_ids])
      : [];
    return { ...list, item_ids, is_shared: true, shared_with: [], shared_items };
  }));

  res.json([...ownLists, ...sharedLists]);
}));

router.post('/api/lists', verifyToken, requireJSON, ar(async (req, res) => {
  const { name, description = '', item_ids = [] } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });

  const qr_token = crypto.randomBytes(12).toString('hex');
  const now      = Math.floor(Date.now() / 1000);
  const list     = await db.getOne(
    'INSERT INTO lists (user_id, name, description, qr_token, created_at, modified_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.user.userId, name.trim(), description, qr_token, now, now]
  );

  for (const id of item_ids) {
    await db.query(
      'INSERT INTO list_items (list_id, item_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [list.id, id]
    );
  }

  res.status(201).json(await listWithItems(list));
}));

router.put('/api/lists/:id', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!await db.getOne('SELECT id FROM lists WHERE id = $1 AND user_id = $2', [listId, userId]))
    return res.status(404).json({ error: 'Not found' });

  const { name, description = '', item_ids = [] } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });

  const now  = Math.floor(Date.now() / 1000);
  const list = await db.getOne(
    'UPDATE lists SET name=$1, description=$2, modified_at=$3 WHERE id=$4 RETURNING *',
    [name.trim(), description, now, listId]
  );

  await db.query('DELETE FROM list_items WHERE list_id = $1', [listId]);
  for (const id of item_ids) {
    await db.query(
      'INSERT INTO list_items (list_id, item_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [listId, id]
    );
  }

  res.json(await listWithItems(list));
}));

router.delete('/api/lists/:id', verifyToken, ar(async (req, res) => {
  const listId = Number(req.params.id);
  await db.query('DELETE FROM lists WHERE id = $1 AND user_id = $2', [listId, req.user.userId]);
  res.json({ ok: true });
}));

router.post('/api/lists/:id/shares', verifyToken, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!await db.getOne('SELECT id FROM lists WHERE id = $1 AND user_id = $2', [listId, userId]))
    return res.status(404).json({ error: 'Not found' });

  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  const target = await db.getOne('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [email.trim()]);
  if (!target) return res.status(404).json({ error: 'No account found with that email' });
  if (target.id === userId) return res.status(400).json({ error: 'Cannot share with yourself' });

  try {
    await db.query(
      'INSERT INTO list_shares (list_id, owner_id, shared_with_id) VALUES ($1,$2,$3)',
      [listId, userId, target.id]
    );
    res.json({ id: target.id, email: target.email });
  } catch {
    res.status(409).json({ error: 'Already shared with this user' });
  }
}));

router.delete('/api/lists/:id/shares/:sharedWithId', verifyToken, ar(async (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);
  if (!await db.getOne('SELECT id FROM lists WHERE id = $1 AND user_id = $2', [listId, userId]))
    return res.status(404).json({ error: 'Not found' });

  await db.query(
    'DELETE FROM list_shares WHERE list_id = $1 AND shared_with_id = $2',
    [listId, Number(req.params.sharedWithId)]
  );
  res.json({ ok: true });
}));

router.delete('/api/shared-lists/:listId', verifyToken, ar(async (req, res) => {
  await db.query(
    'DELETE FROM list_shares WHERE list_id = $1 AND shared_with_id = $2',
    [Number(req.params.listId), req.user.userId]
  );
  res.json({ ok: true });
}));

router.get('/api/lists/:id/qr', verifyToken, ar(async (req, res) => {
  const { userId } = req.user;
  const listId = Number(req.params.id);

  let list = await db.getOne('SELECT qr_token FROM lists WHERE id = $1 AND user_id = $2', [listId, userId]);
  if (!list) {
    list = await db.getOne(
      `SELECT l.qr_token FROM list_shares ls JOIN lists l ON l.id = ls.list_id
       WHERE ls.list_id = $1 AND ls.shared_with_id = $2`,
      [listId, userId]
    );
  }
  if (!list) return res.status(404).json({ error: 'Not found' });

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host  = req.headers['x-forwarded-host']  || req.get('host');
  try {
    const svg = await QRCode.toString(`${proto}://${host}/l/${list.qr_token}`,
      { type: 'svg', margin: 2, width: 256, color: { dark: '#22d45a', light: '#080c09' } });
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send(svg);
  } catch {
    res.status(500).json({ error: 'QR generation failed' });
  }
}));

// ── Public list page ──────────────────────────────────────────────────────────
router.get('/l/:token', qrLimiter, ar(async (req, res) => {
  const list = await db.getOne('SELECT * FROM lists WHERE qr_token = $1', [req.params.token]);
  if (!list) return res.status(404).send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Not Found — SHIT</title>
    <style>body{background:#080c09;color:#b4e8b0;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}</style>
    </head><body><div><h1 style="font-size:18px;letter-spacing:2px">▌▌ SHIT</h1><p>List not found.</p></div></body></html>`);

  const itemIds   = (await db.getAll('SELECT item_id FROM list_items WHERE list_id = $1', [list.id])).map(r => r.item_id);
  const listItems = itemIds.length
    ? await db.getAll('SELECT * FROM items WHERE id = ANY($1)', [itemIds])
    : [];
  const condColor = { new: '#22d45a', good: '#22d45a', fair: '#d4a020', poor: '#d44020' };

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escHtml(list.name)} — SHIT</title>
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
  <div><div class="logo">▌▌ SHIT</div><div class="logo-sub">SIMPLE HOME ITEM TRACKER</div></div>
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
<a class="open-link" href="/">OPEN IN SHIT →</a>
<div class="footer">SHIT // SIMPLE HOME ITEM TRACKER &nbsp;&nbsp;·&nbsp;&nbsp; © 2025 JUICE LEE PRODUCTIONS</div>
</body>
</html>`);
}));

// ── Categories ────────────────────────────────────────────────────────────────
router.get('/api/categories', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT id, name FROM categories WHERE user_id = $1 ORDER BY name',
    [req.user.userId]
  );
  res.json(rows);
}));

router.post('/api/categories', verifyToken, requireJSON, ar(async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    const row = await db.getOne(
      'INSERT INTO categories (user_id, name) VALUES ($1,$2) RETURNING id, name',
      [req.user.userId, name.trim()]
    );
    res.status(201).json(row);
  } catch {
    res.status(409).json({ error: 'Category already exists' });
  }
}));

router.delete('/api/categories/:id', verifyToken, ar(async (req, res) => {
  await db.query(
    'DELETE FROM categories WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  res.json({ ok: true });
}));

// ── Locations ─────────────────────────────────────────────────────────────────
router.get('/api/locations', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT id, name FROM locations WHERE user_id = $1 ORDER BY name',
    [req.user.userId]
  );
  res.json(rows);
}));

router.post('/api/locations', verifyToken, requireJSON, ar(async (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  try {
    const row = await db.getOne(
      'INSERT INTO locations (user_id, name) VALUES ($1,$2) RETURNING id, name',
      [req.user.userId, name.trim()]
    );
    res.status(201).json(row);
  } catch {
    res.status(409).json({ error: 'Location already exists' });
  }
}));

router.delete('/api/locations/:id', verifyToken, ar(async (req, res) => {
  await db.query(
    'DELETE FROM locations WHERE id = $1 AND user_id = $2',
    [Number(req.params.id), req.user.userId]
  );
  res.json({ ok: true });
}));

// ── Account ───────────────────────────────────────────────────────────────────
router.post('/api/account/password', verifyToken, authLimiter, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: 'Password must be 12+ characters, or 8+ characters with at least one number or symbol' });

  const user  = await db.getOne('SELECT password_hash FROM users WHERE id = $1', [userId]);
  const match = await bcrypt.compare(currentPassword, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

  const hash = await bcrypt.hash(newPassword, 10);
  await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
  res.json({ ok: true });
}));

router.delete('/api/account', verifyToken, authLimiter, requireJSON, ar(async (req, res) => {
  const { userId } = req.user;
  const { password } = req.body || {};
  const user  = await db.getOne('SELECT password_hash FROM users WHERE id = $1', [userId]);
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Password is incorrect' });

  // Cascade deletes are handled by FK ON DELETE CASCADE in the schema.
  await db.query('DELETE FROM users WHERE id = $1', [userId]);
  res.json({ ok: true });
}));

// ── Export / Import ───────────────────────────────────────────────────────────
router.get('/api/export', verifyToken, ar(async (req, res) => {
  const items = (await db.getAll('SELECT * FROM items WHERE user_id = $1', [req.user.userId])).map(itemToJSON);
  res.setHeader('Content-Disposition', 'attachment; filename="shit-export.json"');
  res.json({ version: 1, exported: new Date().toISOString(), items });
}));

router.post('/api/import', verifyToken, requireJSON, ar(async (req, res) => {
  const { items = [] } = req.body || {};
  const { userId }     = req.user;
  const now = Math.floor(Date.now() / 1000);
  let count = 0;

  for (const item of items) {
    if (!item.name) continue;
    try {
      await db.query(`
        INSERT INTO items
          (user_id, name, description, category, location, quantity, unit, value,
           brand, model, serial, condition, notes, tags, qr_token, created_at, modified_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      `, [
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
}));

// ── QR Code Sheet PDF ────────────────────────────────────────────────────────
router.post('/api/items/qr-sheet', verifyToken, requireJSON, ar(async (req, res) => {
  const { item_ids } = req.body || {};
  if (!Array.isArray(item_ids) || !item_ids.length)
    return res.status(400).json({ error: 'item_ids required' });

  const ids = item_ids.map(Number).filter(n => Number.isFinite(n) && n > 0);
  if (!ids.length) return res.status(400).json({ error: 'No valid IDs' });

  const placeholders = ids.map((_, i) => `$${i + 2}`).join(',');
  const rows = await db.getAll(
    `SELECT id, name, qr_token FROM items WHERE id IN (${placeholders}) AND user_id = $1`,
    [req.user.userId, ...ids]
  );
  const byId = Object.fromEntries(rows.map(r => [r.id, r]));
  const orderedItems = ids.map(id => byId[id]).filter(Boolean);
  if (!orderedItems.length) return res.status(404).json({ error: 'No matching items' });

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host  = req.headers['x-forwarded-host']  || req.get('host');

  // Layout constants (1 pt = 1/72 inch)
  const IN = 72;
  const MARGIN  = 0.5 * IN;          // 36pt
  const CELL_W  = 1.5 * IN;          // 108pt  — cell width
  const QR_SIZE = 1.0 * IN;          // 72pt   — 1" QR
  const PAD_TOP = 7, PAD_BOT = 7, GAP = 4, NAME_H = 16;
  const CELL_H  = PAD_TOP + QR_SIZE + GAP + NAME_H + PAD_BOT; // ~106pt ≈ 1.47"
  const COLS    = Math.floor((8.5 * IN - 2 * MARGIN) / CELL_W);  // 5
  const ROWS    = Math.floor((11  * IN - 2 * MARGIN) / CELL_H);  // 6
  const PER_PAGE = COLS * ROWS;

  const doc = new PDFDocument({ size: 'LETTER', margin: 0, info: {
    Title: 'QR Code Sheet', Author: 'SHIT Inventory',
  }});

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="qr-sheet.pdf"');
  doc.pipe(res);

  for (let i = 0; i < orderedItems.length; i++) {
    if (i > 0 && i % PER_PAGE === 0) doc.addPage();

    const pos  = i % PER_PAGE;
    const col  = pos % COLS;
    const row  = Math.floor(pos / COLS);
    const x    = MARGIN + col * CELL_W;
    const y    = MARGIN + row * CELL_H;

    // Cut border
    doc.rect(x, y, CELL_W, CELL_H).strokeColor('#bbbbbb').lineWidth(0.5).stroke();

    // QR code (black on white for reliable scanning when printed)
    const url = `${proto}://${host}/i/${orderedItems[i].qr_token}`;
    const qrBuf = await QRCode.toBuffer(url, {
      type: 'png', margin: 1, width: 144,
      color: { dark: '#000000', light: '#ffffff' },
    });
    const qrX = x + (CELL_W - QR_SIZE) / 2;
    const qrY = y + PAD_TOP;
    doc.image(qrBuf, qrX, qrY, { width: QR_SIZE, height: QR_SIZE });

    // Item name (truncate to ~24 chars)
    const name = orderedItems[i].name;
    const label = name.length > 24 ? name.slice(0, 23) + '…' : name;
    doc.font('Helvetica').fontSize(7).fillColor('#111111')
       .text(label, x + 2, qrY + QR_SIZE + GAP, { width: CELL_W - 4, align: 'center', lineBreak: false });
  }

  doc.end();
}));

// ── White Paper PDF ───────────────────────────────────────────────────────────
router.get('/whitepaper.pdf', (req, res) => {
  const doc = new PDFDocument({ margin: 72, size: 'LETTER', info: {
    Title: 'SHIT: Simple Home Item Tracker — White Paper',
    Author: 'Juice Lee Productions',
    Subject: 'Product white paper for the SHIT personal inventory system',
  }});

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="SHIT-whitepaper.pdf"');
  doc.pipe(res);

  const GREEN = '#22d45a', DARK = '#0a0f0b', GRAY = '#555', BLACK = '#111';
  const W = doc.page.width - 144;

  const h1 = (txt) => { doc.moveDown(1.2).font('Helvetica-Bold').fontSize(14).fillColor(GREEN).text(txt).moveDown(0.3).rect(doc.x,doc.y,W,1).fill(GREEN).moveDown(0.6).fillColor(BLACK); };
  const h2 = (txt) => { doc.moveDown(0.8).font('Helvetica-Bold').fontSize(11).fillColor(DARK).text(txt).moveDown(0.3).fillColor(BLACK); };
  const body = (txt, opts={}) => { doc.font('Helvetica').fontSize(10).fillColor(BLACK).text(txt,{lineGap:3,...opts}).moveDown(0.4); };
  const bullet = (items) => { items.forEach(i => doc.font('Helvetica').fontSize(10).fillColor(BLACK).text(`• ${i}`,{lineGap:3,indent:12})); doc.moveDown(0.4); };
  const tableRow = (key,val) => { const y=doc.y; doc.font('Helvetica-Bold').fontSize(9).fillColor(GRAY).text(key,{continued:false,width:140}); doc.font('Helvetica').fontSize(9).fillColor(BLACK).text(val,72+148,y,{width:W-148}); doc.moveDown(0.2); };

  doc.rect(0,0,doc.page.width,180).fill(DARK);
  doc.font('Courier-Bold').fontSize(36).fillColor(GREEN).text('▌▌ SHIT',72,52);
  doc.font('Courier').fontSize(11).fillColor('#aaa').text('SIMPLE HOME ITEM TRACKER',72,100);
  doc.font('Helvetica').fontSize(9).fillColor('#666').text('WHITE PAPER  ·  v1.7.7  ·  © 2025 Juice Lee Productions',72,124);
  doc.rect(72,148,W,1).fill(GREEN);
  doc.y=200;

  h1('1. Executive Summary');
  body('SHIT (Simple Home Item Tracker) is a self-hosted, privacy-first personal inventory management system for the home. It provides a unified platform to catalog physical possessions, track their location and condition, manage loans, and attach documentation — all accessible from any device via a Progressive Web App (PWA).');
  body('AI-assisted item entry, QR code tagging, and collaborative list sharing reduce friction at every step of managing a home inventory. Because the application is self-hosted, all inventory data stays on hardware the owner controls.');

  h1('2. The Problem');
  body('Homeowners, renters, and hobbyists accumulate large numbers of physical items without a reliable way to track them. The consequences are predictable:');
  bullet(['Duplicate purchases — items are bought again because they cannot be located or their existence is forgotten.','Lost loans — items lent to friends or family are never returned because there is no record.','Insurance gaps — without a current inventory and estimated values, claims after loss or disaster are hard to substantiate.','Disorganized storage — without a searchable catalog tied to physical locations, retrieval is time-consuming.']);
  body('SHIT fills the gap: a focused, self-hosted tool that puts the user in full control of their data.');

  h1('3. Key Features');
  [['Item CRUD','Rich metadata: name, brand, model, serial, category, location, condition, value, tags, photo'],['QR Tagging','Unique token per item; public scan page requires no login'],['Checkout Tracking','Borrower, destination, date, due date — full audit trail'],['Collections','Named lists with per-user sharing'],['AI Entry','Claude Haiku extracts metadata from a photo automatically'],['Document Vault','Receipts, warranties, manuals attached to items'],['Export / Import','Full JSON backup and restore'],['PWA / Offline','Installable app with service-worker offline cache']].forEach(([k,v])=>tableRow(k,v));

  doc.addPage();
  h1('4. Technical Architecture');
  h2('4.1 Stack');
  [['Runtime','Node.js + Express.js 4.18'],['Database','PostgreSQL (via node-postgres pool)'],['Auth','JWT 7-day expiry + bcryptjs 10 rounds'],['Rate Limiting','express-rate-limit on auth, AI, upload, and QR routes'],['Security','Helmet 7 (CSP, HSTS, X-Frame-Options)'],['AI','Anthropic SDK — Claude Haiku'],['Frontend','Vanilla JS, Share Tech Mono font'],['PWA','Service Worker v1.8.1, Web App Manifest']].forEach(([k,v])=>tableRow(k,v));

  h2('4.2 Security Model');
  bullet(['Parameterized queries throughout — no SQL injection surface','bcrypt at work factor 10; JWT secret from environment variable','Rate limiting on auth (20/15 min), AI (10/5 min), uploads (30/hr), QR pages (30/15 min)','Content-Type: application/json enforced on all mutation endpoints','owner_email never returned on public QR routes','ON DELETE CASCADE foreign keys prevent orphaned data']);

  h1('5. Conclusion');
  body('SHIT provides a complete, self-contained solution to the real and underserved problem of personal home inventory management. For individuals and households who want to know what they own, where it is, who has it, and what it is worth, SHIT is purpose-built to answer all four questions.');

  doc.moveDown(2).rect(72,doc.y,W,1).fill(GREEN).moveDown(0.6).font('Helvetica').fontSize(8).fillColor(GRAY).text('© 2025 Juice Lee Productions  ·  SHIT v1.7.7  ·  Self-hosted personal inventory management',{align:'center'});
  doc.end();
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  if (!process.env.DATABASE_URL) {
    console.error('ERROR: DATABASE_URL environment variable is required.');
    process.exit(1);
  }

  await db.initialize();

  // JWT secret: prefer env var, fall back to value stored in DB.
  JWT_SECRET = process.env.JWT_SECRET || null;
  if (!JWT_SECRET) {
    const row = await db.getOne("SELECT value FROM store WHERE key = 'jwt_secret'");
    if (row) {
      JWT_SECRET = row.value;
    } else {
      JWT_SECRET = crypto.randomBytes(48).toString('hex');
      await db.query("INSERT INTO store (key, value) VALUES ('jwt_secret', $1)", [JWT_SECRET]);
    }
  }

  app.use(BASE, router);
  app.listen(PORT, () => console.log(`SHIT running → http://localhost:${PORT} (base: ${BASE})`));
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
