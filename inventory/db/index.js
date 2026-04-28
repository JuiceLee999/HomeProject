const { Pool, types } = require('pg');

// pg returns BIGINT/BIGSERIAL (OID 20) as strings to avoid overflow.
// For this app IDs will never exceed MAX_SAFE_INTEGER, so parse as numbers
// so that === comparisons against card dataset values work correctly.
types.setTypeParser(20, val => parseInt(val, 10));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Disable SSL for localhost; use permissive SSL for hosted providers.
  // For strict SSL (DigitalOcean managed DB, Neon), set DATABASE_SSL=strict.
  ...(process.env.DATABASE_URL?.includes('localhost') || process.env.DATABASE_URL?.includes('127.0.0.1')
    ? {}
    : process.env.DATABASE_SSL === 'strict'
      ? { ssl: { rejectUnauthorized: true } }
      : { ssl: { rejectUnauthorized: false } }
  ),
});

pool.on('error', (err) => console.error('PostgreSQL pool error:', err));

async function query(text, params) {
  return pool.query(text, params);
}

async function getOne(text, params) {
  const { rows } = await pool.query(text, params);
  return rows[0] || null;
}

async function getAll(text, params) {
  const { rows } = await pool.query(text, params);
  return rows;
}

async function initialize() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS store (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id             BIGSERIAL PRIMARY KEY,
        email          TEXT UNIQUE NOT NULL,
        password_hash  TEXT NOT NULL,
        last_logout_at BIGINT DEFAULT 0,
        created_at     BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id      BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name    TEXT NOT NULL,
        UNIQUE(user_id, name)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS locations (
        id      BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name    TEXT NOT NULL,
        UNIQUE(user_id, name)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS items (
        id                   BIGSERIAL PRIMARY KEY,
        user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name                 TEXT NOT NULL,
        description          TEXT NOT NULL DEFAULT '',
        category             TEXT NOT NULL DEFAULT '',
        location             TEXT NOT NULL DEFAULT '',
        quantity             NUMERIC NOT NULL DEFAULT 1,
        unit                 TEXT NOT NULL DEFAULT 'pcs',
        value                NUMERIC NOT NULL DEFAULT 0,
        brand                TEXT NOT NULL DEFAULT '',
        model                TEXT NOT NULL DEFAULT '',
        serial               TEXT NOT NULL DEFAULT '',
        condition            TEXT NOT NULL DEFAULT 'good',
        notes                TEXT NOT NULL DEFAULT '',
        tags                 TEXT NOT NULL DEFAULT '[]',
        qr_token             TEXT UNIQUE NOT NULL,
        image_data           TEXT DEFAULT NULL,
        purchased_at         TEXT DEFAULT NULL,
        checked_out_to       TEXT DEFAULT NULL,
        checked_out_at       BIGINT DEFAULT NULL,
        due_back             BIGINT DEFAULT NULL,
        checkout_destination TEXT DEFAULT NULL,
        created_at           BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        modified_at          BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS lists (
        id          BIGSERIAL PRIMARY KEY,
        user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        qr_token    TEXT UNIQUE NOT NULL,
        created_at  BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        modified_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS list_shares (
        id             BIGSERIAL PRIMARY KEY,
        list_id        BIGINT NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
        owner_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        shared_with_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at     BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        UNIQUE(list_id, shared_with_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS list_items (
        list_id BIGINT NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
        item_id BIGINT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
        PRIMARY KEY (list_id, item_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id         BIGSERIAL PRIMARY KEY,
        item_id    BIGINT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
        user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        filename   TEXT NOT NULL,
        mime_type  TEXT NOT NULL DEFAULT '',
        size       BIGINT NOT NULL DEFAULT 0,
        data       TEXT NOT NULL,
        thumb_data TEXT DEFAULT NULL,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS checkouts (
        id          BIGSERIAL PRIMARY KEY,
        item_id     BIGINT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
        user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        borrower    TEXT NOT NULL,
        destination TEXT NOT NULL DEFAULT '',
        checked_out BIGINT NOT NULL,
        due_back    BIGINT DEFAULT NULL,
        checked_in  BIGINT DEFAULT NULL,
        notes       TEXT NOT NULL DEFAULT ''
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        token_hash  TEXT PRIMARY KEY,
        user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at  BIGINT NOT NULL
      )
    `);

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { query, getOne, getAll, initialize, pool };
