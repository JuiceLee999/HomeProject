const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const path      = require('path');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const nodemailer = require('nodemailer');
const Stripe    = require('stripe');
const db        = require('./db/index');

const app  = express();
const PORT = process.env.PORT || 3006;
let JWT_SECRET;
let stripe;

const mailer = nodemailer.createTransport({
  host:   process.env.EMAIL_HOST,
  port:   Number(process.env.EMAIL_PORT) || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth:   { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// ── Helpers ───────────────────────────────────────────────────────────────────
const ar = fn => (req, res, next) => fn(req, res, next).catch(next);

function isValidEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

function isStrongPassword(p) {
  if (!p) return false;
  if (p.length >= 12) return true;
  return p.length >= 8 && /[0-9!@#$%^&*()\-_=+[\]{};':",.<>?/\\|`~]/.test(p);
}

function requireJSON(req, res, next) {
  if (!req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
  next();
}

function isValidDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s);
  return !isNaN(d.getTime());
}

function nightsBetween(checkIn, checkOut) {
  const a = new Date(checkIn);
  const b = new Date(checkOut);
  return Math.round((b - a) / 86400000);
}

function parseListing(row) {
  if (!row) return null;
  return { ...row, amenities: JSON.parse(row.amenities || '[]') };
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Stripe webhook needs raw body — register BEFORE express.json
const BASE = process.env.BASE_PATH || '/camp';
app.use(`${BASE}/api/stripe/webhook`, express.raw({ type: 'application/json' }));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'", "https://js.stripe.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:", "blob:"],
      connectSrc:    ["'self'", "https://api.stripe.com"],
      frameSrc:      ["https://js.stripe.com", "https://hooks.stripe.com"],
      objectSrc:     ["'none'"],
      baseUri:       ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '25mb' }));

const router = express.Router();
router.use(express.static(path.join(__dirname, 'public')));

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Upload limit reached, please try again later.' }
});

// ── Auth middleware ───────────────────────────────────────────────────────────
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

async function requireHost(req, res, next) {
  await verifyToken(req, res, () => {
    if (req.user.role !== 'host') return res.status(403).json({ error: 'Host account required' });
    next();
  });
}

// ── Config ────────────────────────────────────────────────────────────────────
router.get('/api/config', (req, res) => {
  res.json({ stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '' });
});

// ── Auth ──────────────────────────────────────────────────────────────────────
router.post('/api/register', authLimiter, requireJSON, ar(async (req, res) => {
  const { email, password, role = 'guest', display_name = '' } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be 12+ characters, or 8+ with a number or symbol' });
  if (!['guest', 'host'].includes(role)) return res.status(400).json({ error: 'Role must be guest or host' });

  const exists = await db.getOne('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  if (exists) return res.status(409).json({ error: 'An account with that email already exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = await db.getOne(
    'INSERT INTO users (email, password_hash, role, display_name) VALUES ($1,$2,$3,$4) RETURNING id, email, role',
    [email.toLowerCase(), hash, role, display_name.trim()]
  );
  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, role: user.role });
}));

router.post('/api/login', authLimiter, requireJSON, ar(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await db.getOne(
    'SELECT id, email, password_hash, role FROM users WHERE LOWER(email) = LOWER($1)',
    [email]
  );
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email, role: user.role });
}));

router.post('/api/logout', verifyToken, requireJSON, ar(async (req, res) => {
  await db.query('UPDATE users SET last_logout_at = $1 WHERE id = $2', [Date.now(), req.user.userId]);
  res.json({ ok: true });
}));

router.get('/api/me', verifyToken, ar(async (req, res) => {
  const user = await db.getOne(
    'SELECT id, email, role, display_name, avatar_data, stripe_account_status, created_at FROM users WHERE id = $1',
    [req.user.userId]
  );
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
}));

router.put('/api/me', verifyToken, requireJSON, ar(async (req, res) => {
  const { display_name, avatar_data } = req.body || {};
  await db.query(
    'UPDATE users SET display_name = COALESCE($1, display_name), avatar_data = COALESCE($2, avatar_data) WHERE id = $3',
    [display_name?.trim() || null, avatar_data || null, req.user.userId]
  );
  res.json({ ok: true });
}));

router.post('/api/auth/forgot-password', resetLimiter, requireJSON, ar(async (req, res) => {
  const { email } = req.body || {};
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });

  const user = await db.getOne('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
  if (user) {
    const rawToken  = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000;

    await db.query('DELETE FROM password_resets WHERE user_id = $1', [user.id]);
    await db.query(
      'INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1,$2,$3)',
      [tokenHash, user.id, expiresAt]
    );

    const proto    = req.headers['x-forwarded-proto'] || req.protocol;
    const host     = req.headers['x-forwarded-host']  || req.get('host');
    const resetUrl = `${proto}://${host}${BASE}?reset=${rawToken}`;

    await mailer.sendMail({
      from:    process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to:      email,
      subject: 'Reset your Himpcamp password',
      text:    `You requested a password reset.\n\nClick below to set a new password (expires in 1 hour):\n\n${resetUrl}\n\nIf you didn't request this, ignore this email.`,
      html:    `<p>You requested a password reset for your Himpcamp account.</p><p><a href="${resetUrl}">Reset your password →</a></p><p>Link expires in 1 hour.</p>`,
    }).catch(() => {});
  }
  res.json({ ok: true });
}));

router.post('/api/auth/reset-password', resetLimiter, requireJSON, ar(async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be 12+ characters, or 8+ with a number or symbol' });

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

  const user = await db.getOne('SELECT id, email, role FROM users WHERE id = $1', [row.user_id]);
  const newToken = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token: newToken, email: user.email, role: user.role });
}));

// ── Public — Listings ─────────────────────────────────────────────────────────
router.get('/api/listings', ar(async (req, res) => {
  const { city = '', state = '', site_type = '', check_in, check_out, guests, page = 1 } = req.query;
  const limit  = 20;
  const offset = (parseInt(page) - 1) * limit;

  const params = [];
  const conds  = ['l.is_published = TRUE', 'l.is_active = TRUE'];

  if (city.trim()) {
    params.push(`%${city.trim().toLowerCase()}%`);
    conds.push(`LOWER(l.city) LIKE $${params.length}`);
  }
  if (state.trim()) {
    params.push(`%${state.trim().toLowerCase()}%`);
    conds.push(`LOWER(l.state) LIKE $${params.length}`);
  }
  if (site_type.trim()) {
    params.push(site_type.trim());
    conds.push(`l.site_type = $${params.length}`);
  }
  if (guests) {
    params.push(parseInt(guests));
    conds.push(`l.max_guests >= $${params.length}`);
  }

  // Exclude listings that have a confirmed booking overlapping the requested dates
  if (check_in && check_out && isValidDate(check_in) && isValidDate(check_out)) {
    params.push(check_in, check_out);
    const ci = params.length - 1;
    const co = params.length;
    conds.push(`
      NOT EXISTS (
        SELECT 1 FROM bookings b
        WHERE b.listing_id = l.id
          AND b.status = 'confirmed'
          AND NOT (b.check_out <= $${ci} OR b.check_in >= $${co})
      )
    `);
  }

  const where = conds.join(' AND ');
  params.push(limit, offset);

  const rows = await db.getAll(`
    SELECT
      l.*,
      (SELECT image_data FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order ASC LIMIT 1) AS cover_photo,
      COALESCE(AVG(r.rating)::NUMERIC(3,1), 0) AS avg_rating,
      COUNT(DISTINCT r.id) AS review_count,
      u.display_name AS host_name
    FROM listings l
    LEFT JOIN reviews r ON r.listing_id = l.id
    LEFT JOIN users u ON u.id = l.host_id
    WHERE ${where}
    GROUP BY l.id, u.display_name
    ORDER BY l.created_at DESC
    LIMIT $${params.length - 1} OFFSET $${params.length}
  `, params);

  res.json(rows.map(parseListing));
}));

router.get('/api/listings/:id', ar(async (req, res) => {
  const listing = await db.getOne(`
    SELECT l.*, u.display_name AS host_name, u.avatar_data AS host_avatar,
      COALESCE(AVG(r.rating)::NUMERIC(3,1), 0) AS avg_rating,
      COUNT(DISTINCT r.id) AS review_count
    FROM listings l
    LEFT JOIN reviews r ON r.listing_id = l.id
    LEFT JOIN users u ON u.id = l.host_id
    WHERE l.id = $1 AND l.is_published = TRUE AND l.is_active = TRUE
    GROUP BY l.id, u.display_name, u.avatar_data
  `, [req.params.id]);

  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const photos  = await db.getAll('SELECT id, image_data, caption, sort_order FROM listing_photos WHERE listing_id = $1 ORDER BY sort_order ASC', [listing.id]);
  const reviews = await db.getAll(`
    SELECT r.*, u.display_name AS reviewer_name
    FROM reviews r
    JOIN users u ON u.id = r.guest_id
    WHERE r.listing_id = $1
    ORDER BY r.created_at DESC
    LIMIT 20
  `, [listing.id]);

  res.json({ ...parseListing(listing), photos, reviews });
}));

router.get('/api/listings/:id/availability', ar(async (req, res) => {
  const { id } = req.params;

  const booked = await db.getAll(
    `SELECT check_in AS start_date, check_out AS end_date FROM bookings
     WHERE listing_id = $1 AND status = 'confirmed'`,
    [id]
  );
  const blocked = await db.getAll(
    'SELECT start_date, end_date FROM availability_blocks WHERE listing_id = $1',
    [id]
  );

  res.json({ booked, blocked });
}));

// ── Host — Listings ───────────────────────────────────────────────────────────
router.get('/api/host/listings', requireHost, ar(async (req, res) => {
  const rows = await db.getAll(
    `SELECT l.*,
      (SELECT image_data FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order ASC LIMIT 1) AS cover_photo,
      COALESCE(AVG(r.rating)::NUMERIC(3,1), 0) AS avg_rating,
      COUNT(DISTINCT r.id) AS review_count
     FROM listings l
     LEFT JOIN reviews r ON r.listing_id = l.id
     WHERE l.host_id = $1 AND l.is_active = TRUE
     GROUP BY l.id
     ORDER BY l.created_at DESC`,
    [req.user.userId]
  );
  res.json(rows.map(parseListing));
}));

router.post('/api/host/listings', requireHost, requireJSON, ar(async (req, res) => {
  const {
    title, description = '', site_type = 'tent',
    address = '', city = '', state = '',
    lat = null, lng = null,
    price_per_night = 0, max_guests = 2,
    amenities = [], rules = '',
    check_in_time = '15:00', check_out_time = '11:00',
    min_nights = 1, max_nights = 14
  } = req.body || {};

  if (!title || !title.trim()) return res.status(400).json({ error: 'Title is required' });
  const validTypes = ['tent', 'rv', 'cabin', 'glamping', 'farm'];
  if (!validTypes.includes(site_type)) return res.status(400).json({ error: 'Invalid site type' });

  const row = await db.getOne(
    `INSERT INTO listings
      (host_id, title, description, site_type, address, city, state, lat, lng,
       price_per_night, max_guests, amenities, rules, check_in_time, check_out_time, min_nights, max_nights)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
     RETURNING *`,
    [req.user.userId, title.trim(), description, site_type,
     address, city, state, lat, lng,
     price_per_night, max_guests, JSON.stringify(amenities), rules,
     check_in_time, check_out_time, min_nights, max_nights]
  );
  res.status(201).json(parseListing(row));
}));

router.get('/api/host/listings/:id', requireHost, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT * FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const photos = await db.getAll(
    'SELECT id, image_data, caption, sort_order FROM listing_photos WHERE listing_id = $1 ORDER BY sort_order ASC',
    [listing.id]
  );
  const blocks = await db.getAll(
    'SELECT * FROM availability_blocks WHERE listing_id = $1 ORDER BY start_date ASC',
    [listing.id]
  );
  res.json({ ...parseListing(listing), photos, blocks });
}));

router.put('/api/host/listings/:id', requireHost, requireJSON, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const {
    title, description, site_type,
    address, city, state, lat, lng,
    price_per_night, max_guests,
    amenities, rules, check_in_time, check_out_time,
    min_nights, max_nights
  } = req.body || {};

  await db.query(
    `UPDATE listings SET
      title          = COALESCE($1, title),
      description    = COALESCE($2, description),
      site_type      = COALESCE($3, site_type),
      address        = COALESCE($4, address),
      city           = COALESCE($5, city),
      state          = COALESCE($6, state),
      lat            = COALESCE($7, lat),
      lng            = COALESCE($8, lng),
      price_per_night= COALESCE($9, price_per_night),
      max_guests     = COALESCE($10, max_guests),
      amenities      = COALESCE($11, amenities),
      rules          = COALESCE($12, rules),
      check_in_time  = COALESCE($13, check_in_time),
      check_out_time = COALESCE($14, check_out_time),
      min_nights     = COALESCE($15, min_nights),
      max_nights     = COALESCE($16, max_nights),
      modified_at    = EXTRACT(EPOCH FROM NOW())::BIGINT
     WHERE id = $17`,
    [
      title?.trim() || null, description || null, site_type || null,
      address || null, city || null, state || null, lat ?? null, lng ?? null,
      price_per_night ?? null, max_guests ?? null,
      amenities ? JSON.stringify(amenities) : null,
      rules || null, check_in_time || null, check_out_time || null,
      min_nights ?? null, max_nights ?? null,
      listing.id
    ]
  );
  res.json({ ok: true });
}));

router.delete('/api/host/listings/:id', requireHost, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });
  await db.query('UPDATE listings SET is_active = FALSE WHERE id = $1', [listing.id]);
  res.json({ ok: true });
}));

router.post('/api/host/listings/:id/publish', requireHost, requireJSON, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id, is_published FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });
  await db.query('UPDATE listings SET is_published = $1 WHERE id = $2', [!listing.is_published, listing.id]);
  res.json({ is_published: !listing.is_published });
}));

// ── Host — Photos ─────────────────────────────────────────────────────────────
router.post('/api/host/listings/:id/photos', requireHost, uploadLimiter, requireJSON, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const { image_data, caption = '' } = req.body || {};
  if (!image_data || !image_data.startsWith('data:image/')) return res.status(400).json({ error: 'Valid image_data required' });

  const maxOrder = await db.getOne(
    'SELECT COALESCE(MAX(sort_order), -1) AS max FROM listing_photos WHERE listing_id = $1',
    [listing.id]
  );
  const photo = await db.getOne(
    'INSERT INTO listing_photos (listing_id, image_data, caption, sort_order) VALUES ($1,$2,$3,$4) RETURNING id, caption, sort_order',
    [listing.id, image_data, caption, maxOrder.max + 1]
  );
  res.status(201).json(photo);
}));

router.delete('/api/host/listings/:id/photos/:photoId', requireHost, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });
  await db.query('DELETE FROM listing_photos WHERE id = $1 AND listing_id = $2', [req.params.photoId, listing.id]);
  res.json({ ok: true });
}));

router.put('/api/host/listings/:id/photos/reorder', requireHost, requireJSON, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const { order } = req.body || {}; // array of photo IDs in new order
  if (!Array.isArray(order)) return res.status(400).json({ error: 'order must be an array of photo IDs' });

  for (let i = 0; i < order.length; i++) {
    await db.query('UPDATE listing_photos SET sort_order = $1 WHERE id = $2 AND listing_id = $3', [i, order[i], listing.id]);
  }
  res.json({ ok: true });
}));

// ── Host — Availability Blocks ────────────────────────────────────────────────
router.get('/api/host/listings/:id/blocks', requireHost, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });
  const blocks = await db.getAll(
    'SELECT * FROM availability_blocks WHERE listing_id = $1 ORDER BY start_date ASC',
    [listing.id]
  );
  res.json(blocks);
}));

router.post('/api/host/listings/:id/blocks', requireHost, requireJSON, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2 AND is_active = TRUE',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const { start_date, end_date, reason = '' } = req.body || {};
  if (!isValidDate(start_date) || !isValidDate(end_date)) return res.status(400).json({ error: 'Valid start_date and end_date required (YYYY-MM-DD)' });
  if (start_date > end_date) return res.status(400).json({ error: 'start_date must be before end_date' });

  const block = await db.getOne(
    'INSERT INTO availability_blocks (listing_id, start_date, end_date, reason) VALUES ($1,$2,$3,$4) RETURNING *',
    [listing.id, start_date, end_date, reason]
  );
  res.status(201).json(block);
}));

router.delete('/api/host/listings/:id/blocks/:blockId', requireHost, ar(async (req, res) => {
  const listing = await db.getOne(
    'SELECT id FROM listings WHERE id = $1 AND host_id = $2',
    [req.params.id, req.user.userId]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });
  await db.query('DELETE FROM availability_blocks WHERE id = $1 AND listing_id = $2', [req.params.blockId, listing.id]);
  res.json({ ok: true });
}));

// ── Host — Bookings ───────────────────────────────────────────────────────────
router.get('/api/host/bookings', requireHost, ar(async (req, res) => {
  const { status } = req.query;
  const params = [req.user.userId];
  let statusFilter = '';
  if (status) {
    params.push(status);
    statusFilter = `AND bk.status = $${params.length}`;
  }

  const rows = await db.getAll(
    `SELECT bk.*, l.title AS listing_title, u.email AS guest_email, u.display_name AS guest_name
     FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     JOIN users u ON u.id = bk.guest_id
     WHERE l.host_id = $1 ${statusFilter}
     ORDER BY bk.created_at DESC`,
    params
  );
  res.json(rows);
}));

router.get('/api/host/bookings/:id', requireHost, ar(async (req, res) => {
  const booking = await db.getOne(
    `SELECT bk.*, l.title AS listing_title, u.email AS guest_email, u.display_name AS guest_name
     FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     JOIN users u ON u.id = bk.guest_id
     WHERE bk.id = $1 AND l.host_id = $2`,
    [req.params.id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  res.json(booking);
}));

router.post('/api/host/bookings/:id/confirm', requireHost, requireJSON, ar(async (req, res) => {
  const booking = await db.getOne(
    `SELECT bk.id FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     WHERE bk.id = $1 AND l.host_id = $2 AND bk.status = 'pending'`,
    [req.params.id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found or not pending' });
  await db.query(
    "UPDATE bookings SET status = 'confirmed', modified_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $1",
    [booking.id]
  );
  res.json({ ok: true });
}));

router.post('/api/host/bookings/:id/cancel', requireHost, requireJSON, ar(async (req, res) => {
  const booking = await db.getOne(
    `SELECT bk.* FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     WHERE bk.id = $1 AND l.host_id = $2 AND bk.status IN ('pending','confirmed')`,
    [req.params.id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found or already cancelled' });

  const { reason = '' } = req.body || {};

  if (stripe && booking.stripe_payment_intent) {
    try {
      await stripe.refunds.create({ payment_intent: booking.stripe_payment_intent });
    } catch (e) {
      console.error('Stripe refund error:', e.message);
    }
  }

  await db.query(
    `UPDATE bookings SET status = 'cancelled_host', cancelled_at = $1, cancel_reason = $2,
     modified_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $3`,
    [Date.now(), reason, booking.id]
  );
  res.json({ ok: true });
}));

router.get('/api/host/earnings', requireHost, ar(async (req, res) => {
  const rows = await db.getAll(
    `SELECT
       COALESCE(SUM(CASE WHEN bk.status = 'confirmed' THEN bk.host_payout ELSE 0 END), 0) AS total_earned,
       COALESCE(SUM(CASE WHEN bk.status = 'confirmed' AND bk.host_paid_out = FALSE THEN bk.host_payout ELSE 0 END), 0) AS pending_payout,
       COUNT(CASE WHEN bk.status = 'confirmed' THEN 1 END) AS confirmed_bookings,
       l.id AS listing_id, l.title AS listing_title,
       COALESCE(SUM(CASE WHEN bk.status = 'confirmed' THEN bk.host_payout ELSE 0 END), 0) AS listing_earned
     FROM listings l
     LEFT JOIN bookings bk ON bk.listing_id = l.id
     WHERE l.host_id = $1 AND l.is_active = TRUE
     GROUP BY l.id, l.title
     ORDER BY listing_earned DESC`,
    [req.user.userId]
  );
  const totals = rows.reduce((acc, r) => ({
    total_earned: acc.total_earned + parseFloat(r.total_earned),
    pending_payout: acc.pending_payout + parseFloat(r.pending_payout),
    confirmed_bookings: acc.confirmed_bookings + parseInt(r.confirmed_bookings)
  }), { total_earned: 0, pending_payout: 0, confirmed_bookings: 0 });

  res.json({ ...totals, by_listing: rows });
}));

// ── Host — Stripe Connect ─────────────────────────────────────────────────────
router.post('/api/host/stripe/connect', requireHost, requireJSON, ar(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  const user = await db.getOne('SELECT id, email, stripe_account_id FROM users WHERE id = $1', [req.user.userId]);

  let accountId = user.stripe_account_id;
  if (!accountId) {
    const account = await stripe.accounts.create({ type: 'express', email: user.email });
    accountId = account.id;
    await db.query('UPDATE users SET stripe_account_id = $1 WHERE id = $2', [accountId, user.id]);
  }

  const proto   = req.headers['x-forwarded-proto'] || req.protocol;
  const host    = req.headers['x-forwarded-host']  || req.get('host');
  const appUrl  = `${proto}://${host}${BASE}`;

  const link = await stripe.accountLinks.create({
    account:     accountId,
    refresh_url: `${appUrl}/api/host/stripe/connect`,
    return_url:  `${appUrl}?stripe_return=1`,
    type:        'account_onboarding',
  });
  res.json({ url: link.url });
}));

router.get('/api/host/stripe/status', requireHost, ar(async (req, res) => {
  const user = await db.getOne('SELECT stripe_account_id, stripe_account_status FROM users WHERE id = $1', [req.user.userId]);
  if (!user.stripe_account_id || !stripe) return res.json({ status: 'none' });

  try {
    const account = await stripe.accounts.retrieve(user.stripe_account_id);
    const status  = account.charges_enabled ? 'active' : 'pending';
    await db.query('UPDATE users SET stripe_account_status = $1 WHERE id = $2', [status, req.user.userId]);
    res.json({ status });
  } catch {
    res.json({ status: user.stripe_account_status });
  }
}));

// ── Guest — Bookings ──────────────────────────────────────────────────────────
router.post('/api/bookings', verifyToken, requireJSON, ar(async (req, res) => {
  const { listing_id, check_in, check_out, num_guests = 1, guest_message = '' } = req.body || {};

  if (!listing_id) return res.status(400).json({ error: 'listing_id is required' });
  if (!isValidDate(check_in) || !isValidDate(check_out)) return res.status(400).json({ error: 'Valid check_in and check_out dates required (YYYY-MM-DD)' });

  const today = new Date().toISOString().slice(0, 10);
  if (check_in < today) return res.status(400).json({ error: 'Check-in cannot be in the past' });
  if (check_out <= check_in) return res.status(400).json({ error: 'Check-out must be after check-in' });

  const listing = await db.getOne(
    'SELECT * FROM listings WHERE id = $1 AND is_published = TRUE AND is_active = TRUE',
    [listing_id]
  );
  if (!listing) return res.status(404).json({ error: 'Listing not found' });

  const nights = nightsBetween(check_in, check_out);
  if (nights < listing.min_nights) return res.status(400).json({ error: `Minimum stay is ${listing.min_nights} night(s)` });
  if (nights > listing.max_nights) return res.status(400).json({ error: `Maximum stay is ${listing.max_nights} night(s)` });
  if (num_guests > listing.max_guests) return res.status(400).json({ error: `Maximum ${listing.max_guests} guest(s) allowed` });

  // Check availability: no overlapping confirmed bookings or blocks
  const conflict = await db.getOne(`
    SELECT 1 FROM bookings
    WHERE listing_id = $1 AND status = 'confirmed'
      AND NOT (check_out <= $2 OR check_in >= $3)
    UNION ALL
    SELECT 1 FROM availability_blocks
    WHERE listing_id = $1
      AND NOT (end_date < $2 OR start_date > $3)
    LIMIT 1
  `, [listing_id, check_in, check_out]);
  if (conflict) return res.status(409).json({ error: 'Those dates are not available' });

  const subtotal     = parseFloat(listing.price_per_night) * nights;
  const platformFee  = Math.round(subtotal * 0.1 * 100) / 100;
  const hostPayout   = Math.round((subtotal - platformFee) * 100) / 100;
  const totalCharged = Math.round((subtotal + platformFee) * 100) / 100;

  // Create booking record
  const booking = await db.getOne(
    `INSERT INTO bookings
      (listing_id, guest_id, check_in, check_out, num_guests, nights,
       price_per_night, subtotal, platform_fee, host_payout, total_charged, guest_message)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING *`,
    [listing_id, req.user.userId, check_in, check_out, num_guests, nights,
     listing.price_per_night, subtotal, platformFee, hostPayout, totalCharged, guest_message]
  );

  // Stripe Checkout Session
  if (stripe && listing.host_id) {
    const host = await db.getOne('SELECT stripe_account_id FROM users WHERE id = $1', [listing.host_id]);

    if (host?.stripe_account_id) {
      const proto   = req.headers['x-forwarded-proto'] || req.protocol;
      const hostHdr = req.headers['x-forwarded-host']  || req.get('host');
      const appUrl  = `${proto}://${hostHdr}${BASE}`;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            unit_amount: Math.round(totalCharged * 100),
            product_data: { name: listing.title, description: `${check_in} → ${check_out} · ${nights} night(s)` }
          },
          quantity: 1
        }],
        mode: 'payment',
        success_url: `${appUrl}?booking_success=${booking.id}`,
        cancel_url:  `${appUrl}?booking_cancel=${booking.id}`,
        metadata:    { booking_id: String(booking.id) },
        payment_intent_data: {
          application_fee_amount: Math.round(platformFee * 100),
          transfer_data: { destination: host.stripe_account_id }
        }
      });

      await db.query('UPDATE bookings SET stripe_session_id = $1 WHERE id = $2', [session.id, booking.id]);
      return res.status(201).json({ booking_id: booking.id, sessionUrl: session.url });
    }
  }

  // No Stripe: confirm directly (dev mode or host not connected)
  await db.query("UPDATE bookings SET status = 'confirmed' WHERE id = $1", [booking.id]);
  res.status(201).json({ booking_id: booking.id, confirmed: true });
}));

router.get('/api/bookings', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    `SELECT bk.*, l.title AS listing_title,
      (SELECT image_data FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order ASC LIMIT 1) AS listing_photo
     FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     WHERE bk.guest_id = $1
     ORDER BY bk.check_in DESC`,
    [req.user.userId]
  );
  res.json(rows);
}));

router.get('/api/bookings/:id', verifyToken, ar(async (req, res) => {
  const booking = await db.getOne(
    `SELECT bk.*, l.title AS listing_title, l.city, l.state, l.check_in_time, l.check_out_time,
      (SELECT image_data FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order ASC LIMIT 1) AS listing_photo,
      u.display_name AS host_name
     FROM bookings bk
     JOIN listings l ON l.id = bk.listing_id
     JOIN users u ON u.id = l.host_id
     WHERE bk.id = $1 AND bk.guest_id = $2`,
    [req.params.id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  res.json(booking);
}));

router.post('/api/bookings/:id/cancel', verifyToken, requireJSON, ar(async (req, res) => {
  const booking = await db.getOne(
    "SELECT * FROM bookings WHERE id = $1 AND guest_id = $2 AND status IN ('pending','confirmed')",
    [req.params.id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found or cannot be cancelled' });

  // Must be more than 48 hours before check-in
  const checkInTs = new Date(booking.check_in).getTime();
  if (Date.now() > checkInTs - 48 * 60 * 60 * 1000) {
    return res.status(400).json({ error: 'Cancellations must be made at least 48 hours before check-in' });
  }

  if (stripe && booking.stripe_payment_intent) {
    try {
      await stripe.refunds.create({ payment_intent: booking.stripe_payment_intent });
    } catch (e) {
      console.error('Stripe refund error:', e.message);
    }
  }

  await db.query(
    `UPDATE bookings SET status = 'cancelled_guest', cancelled_at = $1,
     modified_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $2`,
    [Date.now(), booking.id]
  );
  res.json({ ok: true });
}));

// ── Reviews ───────────────────────────────────────────────────────────────────
router.post('/api/reviews', verifyToken, requireJSON, ar(async (req, res) => {
  const { booking_id, rating, comment = '' } = req.body || {};
  if (!booking_id) return res.status(400).json({ error: 'booking_id is required' });
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'rating must be 1–5' });

  const booking = await db.getOne(
    "SELECT * FROM bookings WHERE id = $1 AND guest_id = $2 AND status = 'confirmed'",
    [booking_id, req.user.userId]
  );
  if (!booking) return res.status(404).json({ error: 'Booking not found or not eligible for review' });

  const existing = await db.getOne('SELECT id FROM reviews WHERE booking_id = $1', [booking_id]);
  if (existing) return res.status(409).json({ error: 'You have already reviewed this booking' });

  const review = await db.getOne(
    'INSERT INTO reviews (booking_id, listing_id, guest_id, rating, comment) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [booking_id, booking.listing_id, req.user.userId, rating, comment]
  );
  res.status(201).json(review);
}));

router.get('/api/reviews/:listingId', ar(async (req, res) => {
  const rows = await db.getAll(
    `SELECT r.*, u.display_name AS reviewer_name
     FROM reviews r
     JOIN users u ON u.id = r.guest_id
     WHERE r.listing_id = $1
     ORDER BY r.created_at DESC`,
    [req.params.listingId]
  );
  res.json(rows);
}));

// ── Stripe Webhook ────────────────────────────────────────────────────────────
router.post('/api/stripe/webhook', ar(async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).json({ error: `Webhook signature error: ${e.message}` });
  }

  if (event.type === 'checkout.session.completed') {
    const session   = event.data.object;
    const bookingId = parseInt(session.metadata?.booking_id);
    if (bookingId) {
      await db.query(
        `UPDATE bookings SET status = 'confirmed', stripe_payment_intent = $1,
         modified_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $2`,
        [session.payment_intent, bookingId]
      );
    }
  } else if (event.type === 'checkout.session.expired') {
    const session   = event.data.object;
    const bookingId = parseInt(session.metadata?.booking_id);
    if (bookingId) {
      await db.query(
        `UPDATE bookings SET status = 'cancelled_guest', cancelled_at = $1,
         modified_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $2 AND status = 'pending'`,
        [Date.now(), bookingId]
      );
    }
  } else if (event.type === 'account.updated') {
    const account = event.data.object;
    const status  = account.charges_enabled ? 'active' : 'pending';
    await db.query('UPDATE users SET stripe_account_status = $1 WHERE stripe_account_id = $2', [status, account.id]);
  }

  res.json({ received: true });
}));

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

  if (process.env.STRIPE_SECRET_KEY) {
    stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  } else {
    console.warn('STRIPE_SECRET_KEY not set — payments disabled');
  }

  app.use(BASE, router);
  app.listen(PORT, () => console.log(`Himpcamp running → http://localhost:${PORT} (base: ${BASE})`));
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
