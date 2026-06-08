const { Pool, types } = require('pg');

types.setTypeParser(20, val => parseInt(val, 10));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
        id                    BIGSERIAL PRIMARY KEY,
        email                 TEXT UNIQUE NOT NULL,
        password_hash         TEXT NOT NULL,
        role                  TEXT NOT NULL DEFAULT 'guest',
        display_name          TEXT NOT NULL DEFAULT '',
        avatar_data           TEXT DEFAULT NULL,
        stripe_account_id     TEXT DEFAULT NULL,
        stripe_account_status TEXT NOT NULL DEFAULT 'none',
        last_logout_at        BIGINT DEFAULT 0,
        created_at            BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id              BIGSERIAL PRIMARY KEY,
        host_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title           TEXT NOT NULL,
        description     TEXT NOT NULL DEFAULT '',
        site_type       TEXT NOT NULL DEFAULT 'tent',
        address         TEXT NOT NULL DEFAULT '',
        city            TEXT NOT NULL DEFAULT '',
        state           TEXT NOT NULL DEFAULT '',
        lat             NUMERIC DEFAULT NULL,
        lng             NUMERIC DEFAULT NULL,
        price_per_night NUMERIC NOT NULL DEFAULT 0,
        max_guests      INT NOT NULL DEFAULT 2,
        amenities       TEXT NOT NULL DEFAULT '[]',
        rules           TEXT NOT NULL DEFAULT '',
        check_in_time   TEXT NOT NULL DEFAULT '15:00',
        check_out_time  TEXT NOT NULL DEFAULT '11:00',
        min_nights      INT NOT NULL DEFAULT 1,
        max_nights      INT NOT NULL DEFAULT 14,
        is_published    BOOLEAN NOT NULL DEFAULT FALSE,
        is_active       BOOLEAN NOT NULL DEFAULT TRUE,
        created_at      BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        modified_at     BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS listing_photos (
        id         BIGSERIAL PRIMARY KEY,
        listing_id BIGINT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        image_data TEXT NOT NULL,
        caption    TEXT NOT NULL DEFAULT '',
        sort_order INT NOT NULL DEFAULT 0,
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS availability_blocks (
        id         BIGSERIAL PRIMARY KEY,
        listing_id BIGINT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        start_date TEXT NOT NULL,
        end_date   TEXT NOT NULL,
        reason     TEXT NOT NULL DEFAULT '',
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id                    BIGSERIAL PRIMARY KEY,
        listing_id            BIGINT NOT NULL REFERENCES listings(id) ON DELETE RESTRICT,
        guest_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        check_in              TEXT NOT NULL,
        check_out             TEXT NOT NULL,
        num_guests            INT NOT NULL DEFAULT 1,
        nights                INT NOT NULL,
        price_per_night       NUMERIC NOT NULL,
        subtotal              NUMERIC NOT NULL,
        platform_fee          NUMERIC NOT NULL,
        host_payout           NUMERIC NOT NULL,
        total_charged         NUMERIC NOT NULL,
        status                TEXT NOT NULL DEFAULT 'pending',
        stripe_session_id     TEXT DEFAULT NULL,
        stripe_payment_intent TEXT DEFAULT NULL,
        stripe_transfer_id    TEXT DEFAULT NULL,
        host_paid_out         BOOLEAN NOT NULL DEFAULT FALSE,
        guest_message         TEXT NOT NULL DEFAULT '',
        host_notes            TEXT NOT NULL DEFAULT '',
        cancelled_at          BIGINT DEFAULT NULL,
        cancel_reason         TEXT NOT NULL DEFAULT '',
        created_at            BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        modified_at           BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id         BIGSERIAL PRIMARY KEY,
        booking_id BIGINT NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
        listing_id BIGINT NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        guest_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        rating     INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment    TEXT NOT NULL DEFAULT '',
        created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        UNIQUE(booking_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        token_hash TEXT PRIMARY KEY,
        user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at BIGINT NOT NULL
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
