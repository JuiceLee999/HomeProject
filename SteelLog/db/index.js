const { Pool, types } = require('pg');

types.setTypeParser(20, val => parseInt(val, 10));

const pool = new Pool({
  connectionString: process.env.SL_DATABASE_URL,
  ...(process.env.SL_DATABASE_URL?.includes('localhost') || process.env.SL_DATABASE_URL?.includes('127.0.0.1')
    ? {}
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
      CREATE TABLE IF NOT EXISTS equipment (
        id          BIGSERIAL PRIMARY KEY,
        user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name        TEXT NOT NULL,
        category    TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        notes       TEXT NOT NULL DEFAULT '',
        created_at  BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        UNIQUE(user_id, name)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id               BIGSERIAL PRIMARY KEY,
        user_id          BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        contract_number  TEXT NOT NULL DEFAULT '',
        client_name      TEXT NOT NULL,
        client_contact   TEXT NOT NULL DEFAULT '',
        start_date       BIGINT DEFAULT NULL,
        end_date         BIGINT DEFAULT NULL,
        location         TEXT NOT NULL DEFAULT '',
        purpose          TEXT NOT NULL DEFAULT '',
        rate             NUMERIC NOT NULL DEFAULT 0,
        status           TEXT NOT NULL DEFAULT 'active',
        notes            TEXT NOT NULL DEFAULT '',
        created_at       BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
        modified_at      BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS job_equipment (
        job_id       BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        equipment_id BIGINT NOT NULL REFERENCES equipment(id) ON DELETE CASCADE,
        quantity     NUMERIC NOT NULL DEFAULT 1,
        PRIMARY KEY (job_id, equipment_id)
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
