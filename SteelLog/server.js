const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const path      = require('path');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const db        = require('./db/index');

const app  = express();
const PORT = process.env.PORT || 3003;
let JWT_SECRET;

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
      imgSrc:        ["'self'", "data:"],
      connectSrc:    ["'self'"],
      frameSrc:      ["'none'"],
      objectSrc:     ["'none'"],
      baseUri:       ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '10mb' }));

const BASE = process.env.BASE_PATH || '/sl';
const router = express.Router();

// Admin page served before static middleware so /admin doesn't fall through to index.html
router.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
router.use(express.static(path.join(__dirname, 'public')));

// ── Rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' }
});
const publicLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many submissions, please try again later.' }
});

// ── Auth middleware ───────────────────────────────────────────────────────────
async function verifyToken(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.getOne(
      'SELECT id, email, last_logout_at FROM users WHERE id = $1',
      [decoded.id]
    );
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (decoded.iat * 1000 < (user.last_logout_at || 0)) {
      return res.status(401).json({ error: 'Token revoked' });
    }
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth routes ───────────────────────────────────────────────────────────────
router.post('/api/register', authLimiter, ar(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRx.test(email)) return res.status(400).json({ error: 'Invalid email' });
  const strongEnough = password.length >= 12 ||
    (password.length >= 8 && /[^a-zA-Z0-9]/.test(password));
  if (!strongEnough) return res.status(400).json({ error: 'Password must be 12+ chars, or 8+ with a symbol' });
  const existing = await db.getOne('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const hash = await bcrypt.hash(password, 10);
  const user = await db.getOne(
    'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
    [email.toLowerCase(), hash]
  );
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
}));

router.post('/api/login', authLimiter, ar(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = await db.getOne('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
}));

router.post('/api/logout', verifyToken, ar(async (req, res) => {
  await db.query('UPDATE users SET last_logout_at = $1 WHERE id = $2', [Date.now(), req.user.id]);
  res.json({ ok: true });
}));

// ── Public API routes (no auth) ───────────────────────────────────────────────
router.get('/api/public/equipment', ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT id, name, category, description FROM equipment ORDER BY category ASC, name ASC'
  );
  res.json(rows);
}));

router.get('/api/public/services', ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT id, name, description, icon FROM services ORDER BY sort_order ASC, name ASC'
  );
  res.json(rows);
}));

router.get('/api/public/gallery', ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT id, image_data, caption FROM gallery ORDER BY sort_order ASC, created_at DESC'
  );
  res.json(rows);
}));

router.post('/api/public/request', publicLimiter, ar(async (req, res) => {
  const { name, phone = '', email = '', interest = '', start_date, end_date, location = '', notes = '' } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  if (!phone?.trim() && !email?.trim()) return res.status(400).json({ error: 'Phone or email is required' });
  await db.query(
    `INSERT INTO requests (name, phone, email, interest, start_date, end_date, location, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [name.trim(), phone.trim(), email.trim(), interest.trim(),
     start_date || null, end_date || null, location.trim(), notes.trim()]
  );
  res.json({ ok: true });
}));

// ── Equipment routes ──────────────────────────────────────────────────────────
router.get('/api/equipment', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT * FROM equipment WHERE user_id = $1 ORDER BY name ASC',
    [req.user.id]
  );
  res.json(rows);
}));

router.post('/api/equipment', verifyToken, ar(async (req, res) => {
  const { name, category = '', description = '', notes = '' } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const existing = await db.getOne(
    'SELECT id FROM equipment WHERE user_id = $1 AND name = $2',
    [req.user.id, name.trim()]
  );
  if (existing) return res.status(409).json({ error: 'Equipment with that name already exists' });
  const row = await db.getOne(
    `INSERT INTO equipment (user_id, name, category, description, notes)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [req.user.id, name.trim(), category.trim(), description.trim(), notes.trim()]
  );
  res.status(201).json(row);
}));

router.put('/api/equipment/:id', verifyToken, ar(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, category = '', description = '', notes = '' } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const row = await db.getOne(
    `UPDATE equipment SET name=$1, category=$2, description=$3, notes=$4
     WHERE id=$5 AND user_id=$6 RETURNING *`,
    [name.trim(), category.trim(), description.trim(), notes.trim(), id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
}));

router.delete('/api/equipment/:id', verifyToken, ar(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const inUse = await db.getOne(
    `SELECT je.job_id FROM job_equipment je
     JOIN jobs j ON j.id = je.job_id
     WHERE je.equipment_id = $1 AND j.user_id = $2 AND j.status = 'active'
     LIMIT 1`,
    [id, req.user.id]
  );
  if (inUse) return res.status(409).json({ error: 'Equipment is used in an active job' });
  await db.query('DELETE FROM equipment WHERE id = $1 AND user_id = $2', [id, req.user.id]);
  res.json({ ok: true });
}));

// ── Jobs helpers ──────────────────────────────────────────────────────────────
const JOB_WITH_EQUIPMENT = `
  SELECT j.*,
    COALESCE(
      json_agg(
        json_build_object('id', e.id, 'name', e.name, 'category', e.category, 'quantity', je.quantity)
        ORDER BY e.name
      ) FILTER (WHERE e.id IS NOT NULL),
      '[]'
    ) AS equipment
  FROM jobs j
  LEFT JOIN job_equipment je ON je.job_id = j.id
  LEFT JOIN equipment e ON e.id = je.equipment_id
`;

async function upsertJobEquipment(client, jobId, equipmentList) {
  await client.query('DELETE FROM job_equipment WHERE job_id = $1', [jobId]);
  for (const { equipment_id, quantity } of equipmentList) {
    await client.query(
      'INSERT INTO job_equipment (job_id, equipment_id, quantity) VALUES ($1,$2,$3)',
      [jobId, equipment_id, quantity || 1]
    );
  }
}

// ── Jobs routes ───────────────────────────────────────────────────────────────
router.get('/api/jobs', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    JOB_WITH_EQUIPMENT + ' WHERE j.user_id = $1 GROUP BY j.id ORDER BY j.created_at DESC',
    [req.user.id]
  );
  res.json(rows);
}));

router.get('/api/jobs/:id', verifyToken, ar(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const row = await db.getOne(
    JOB_WITH_EQUIPMENT + ' WHERE j.id = $1 AND j.user_id = $2 GROUP BY j.id',
    [id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
}));

router.post('/api/jobs', verifyToken, ar(async (req, res) => {
  const {
    contract_number = '', client_name, client_contact = '',
    start_date, end_date, location = '', purpose = '',
    rate = 0, status = 'active', notes = '', equipment = []
  } = req.body || {};
  if (!client_name?.trim()) return res.status(400).json({ error: 'Client name required' });
  const validStatuses = ['active','completed','invoiced','paid'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const row = await client.query(
      `INSERT INTO jobs (user_id, contract_number, client_name, client_contact,
        start_date, end_date, location, purpose, rate, status, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [req.user.id, contract_number.trim(), client_name.trim(), client_contact.trim(),
       start_date || null, end_date || null, location.trim(), purpose.trim(),
       parseFloat(rate) || 0, status, notes.trim()]
    );
    const job = row.rows[0];
    if (equipment.length) await upsertJobEquipment(client, job.id, equipment);
    await client.query('COMMIT');
    const full = await db.getOne(
      JOB_WITH_EQUIPMENT + ' WHERE j.id = $1 AND j.user_id = $2 GROUP BY j.id',
      [job.id, req.user.id]
    );
    res.status(201).json(full);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

router.put('/api/jobs/:id', verifyToken, ar(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const {
    contract_number, client_name, client_contact,
    start_date, end_date, location, purpose,
    rate, status, notes, equipment = []
  } = req.body || {};
  if (!client_name?.trim()) return res.status(400).json({ error: 'Client name required' });
  const validStatuses = ['active','completed','invoiced','paid'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const row = await client.query(
      `UPDATE jobs SET
        contract_number=$1, client_name=$2, client_contact=$3,
        start_date=$4, end_date=$5, location=$6, purpose=$7,
        rate=$8, status=$9, notes=$10,
        modified_at=EXTRACT(EPOCH FROM NOW())::BIGINT
       WHERE id=$11 AND user_id=$12 RETURNING *`,
      [contract_number?.trim() ?? '', client_name.trim(), client_contact?.trim() ?? '',
       start_date || null, end_date || null, location?.trim() ?? '', purpose?.trim() ?? '',
       parseFloat(rate) || 0, status, notes?.trim() ?? '', id, req.user.id]
    );
    if (!row.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Not found' }); }
    await upsertJobEquipment(client, id, equipment);
    await client.query('COMMIT');
    const full = await db.getOne(
      JOB_WITH_EQUIPMENT + ' WHERE j.id = $1 AND j.user_id = $2 GROUP BY j.id',
      [id, req.user.id]
    );
    res.json(full);
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}));

router.delete('/api/jobs/:id', verifyToken, ar(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  await db.query('DELETE FROM jobs WHERE id = $1 AND user_id = $2', [id, req.user.id]);
  res.json({ ok: true });
}));

// ── Requests routes ───────────────────────────────────────────────────────────
router.get('/api/requests', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll('SELECT * FROM requests ORDER BY created_at DESC');
  res.json(rows);
}));

router.put('/api/requests/:id', verifyToken, ar(async (req, res) => {
  const { status } = req.body || {};
  const valid = ['new','reviewing','converted','declined'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const row = await db.getOne(
    'UPDATE requests SET status=$1 WHERE id=$2 RETURNING *',
    [status, req.params.id]
  );
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
}));

router.delete('/api/requests/:id', verifyToken, ar(async (req, res) => {
  await db.query('DELETE FROM requests WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// ── Services routes ───────────────────────────────────────────────────────────
router.get('/api/services', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT * FROM services WHERE owner_id=$1 ORDER BY sort_order ASC, name ASC',
    [req.user.id]
  );
  res.json(rows);
}));

router.post('/api/services', verifyToken, ar(async (req, res) => {
  const { name, description = '', icon = '', sort_order = 0 } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const row = await db.getOne(
    'INSERT INTO services (owner_id,name,description,icon,sort_order) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [req.user.id, name.trim(), description.trim(), icon.trim(), parseInt(sort_order) || 0]
  );
  res.status(201).json(row);
}));

router.put('/api/services/:id', verifyToken, ar(async (req, res) => {
  const { name, description = '', icon = '', sort_order = 0 } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
  const row = await db.getOne(
    `UPDATE services SET name=$1,description=$2,icon=$3,sort_order=$4
     WHERE id=$5 AND owner_id=$6 RETURNING *`,
    [name.trim(), description.trim(), icon.trim(), parseInt(sort_order) || 0, req.params.id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
}));

router.delete('/api/services/:id', verifyToken, ar(async (req, res) => {
  await db.query('DELETE FROM services WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
}));

// ── Gallery routes ────────────────────────────────────────────────────────────
router.get('/api/gallery', verifyToken, ar(async (req, res) => {
  const rows = await db.getAll(
    'SELECT * FROM gallery WHERE owner_id=$1 ORDER BY sort_order ASC, created_at DESC',
    [req.user.id]
  );
  res.json(rows);
}));

router.post('/api/gallery', verifyToken, ar(async (req, res) => {
  const { image_data, caption = '', sort_order = 0 } = req.body || {};
  if (!image_data) return res.status(400).json({ error: 'Image required' });
  const row = await db.getOne(
    'INSERT INTO gallery (owner_id,image_data,caption,sort_order) VALUES ($1,$2,$3,$4) RETURNING *',
    [req.user.id, image_data, caption.trim(), parseInt(sort_order) || 0]
  );
  res.status(201).json(row);
}));

router.put('/api/gallery/:id', verifyToken, ar(async (req, res) => {
  const { caption = '', sort_order = 0 } = req.body || {};
  const row = await db.getOne(
    'UPDATE gallery SET caption=$1,sort_order=$2 WHERE id=$3 AND owner_id=$4 RETURNING *',
    [caption.trim(), parseInt(sort_order) || 0, req.params.id, req.user.id]
  );
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
}));

router.delete('/api/gallery/:id', verifyToken, ar(async (req, res) => {
  await db.query('DELETE FROM gallery WHERE id=$1 AND owner_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
}));

// ── Error handler ─────────────────────────────────────────────────────────────
router.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use(BASE, router);

// ── Boot ──────────────────────────────────────────────────────────────────────
(async () => {
  if (!process.env.SL_DATABASE_URL) {
    console.error('ERROR: SL_DATABASE_URL is not set');
    process.exit(1);
  }

  await db.initialize();

  JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    const stored = await db.getOne("SELECT value FROM store WHERE key = 'jwt_secret'", []);
    if (stored) {
      JWT_SECRET = stored.value;
    } else {
      JWT_SECRET = crypto.randomBytes(48).toString('hex');
      await db.query("INSERT INTO store (key,value) VALUES ('jwt_secret',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [JWT_SECRET]);
    }
  }

  app.listen(PORT, () => console.log(`SteelLog running on port ${PORT} at ${BASE}`));
})();
