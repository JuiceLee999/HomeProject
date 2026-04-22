#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set.');
  process.exit(1);
}

const SQLITE_PATH = path.join(__dirname, '../db/cache.db');

const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ...(process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1')
    ? {}
    : process.env.DATABASE_SSL === 'strict'
      ? { ssl: { rejectUnauthorized: true } }
      : { ssl: { rejectUnauthorized: false } }
  ),
});

function tableRows(sqliteDb, tableName) {
  const stmt = sqliteDb.prepare(`SELECT * FROM ${tableName}`);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function tableExists(sqliteDb, tableName) {
  const stmt = sqliteDb.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name=:name`
  );
  stmt.bind({ ':name': tableName });
  const exists = stmt.step();
  stmt.free();
  return exists;
}

async function resetSequence(table) {
  await pgPool.query(
    `SELECT setval(pg_get_serial_sequence('${table}', 'id'), COALESCE(MAX(id), 1)) FROM ${table}`
  );
}

async function main() {
  console.log('==> Initializing PostgreSQL schema...');
  const db = require('../db/index');
  await db.initialize();

  console.log('==> Loading SQLite database...');
  if (!fs.existsSync(SQLITE_PATH)) {
    console.error(`ERROR: SQLite file not found at ${SQLITE_PATH}`);
    process.exit(1);
  }
  const SQL = await initSqlJs();
  const fileBuffer = fs.readFileSync(SQLITE_PATH);
  const sqlite = new SQL.Database(fileBuffer);

  const pgClient = await pgPool.connect();
  try {
    await pgClient.query('BEGIN');

    // store
    if (tableExists(sqlite, 'store')) {
      const rows = tableRows(sqlite, 'store');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO store (key, value) VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
          [r.key, r.value]
        );
      }
      console.log(`  store: ${rows.length} rows`);
    }

    // users
    if (tableExists(sqlite, 'users')) {
      const rows = tableRows(sqlite, 'users');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO users (id, email, password_hash, last_logout_at, created_at)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.email, r.password_hash, r.last_logout_at ?? 0, r.created_at ?? 0]
        );
      }
      console.log(`  users: ${rows.length} rows`);
    }

    // categories
    if (tableExists(sqlite, 'categories')) {
      const rows = tableRows(sqlite, 'categories');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO categories (id, user_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.user_id, r.name]
        );
      }
      console.log(`  categories: ${rows.length} rows`);
    }

    // locations
    if (tableExists(sqlite, 'locations')) {
      const rows = tableRows(sqlite, 'locations');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO locations (id, user_id, name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.user_id, r.name]
        );
      }
      console.log(`  locations: ${rows.length} rows`);
    }

    // items
    if (tableExists(sqlite, 'items')) {
      const rows = tableRows(sqlite, 'items');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO items (
             id, user_id, name, description, category, location,
             quantity, unit, value, brand, model, serial,
             condition, notes, tags, qr_token, image_data, purchased_at,
             checked_out_to, checked_out_at, due_back, checkout_destination,
             created_at, modified_at
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
           ) ON CONFLICT (id) DO NOTHING`,
          [
            r.id, r.user_id, r.name,
            r.description ?? '', r.category ?? '', r.location ?? '',
            r.quantity ?? 1, r.unit ?? 'pcs', r.value ?? 0,
            r.brand ?? '', r.model ?? '', r.serial ?? '',
            r.condition ?? 'good', r.notes ?? '', r.tags ?? '[]',
            r.qr_token, r.image_data ?? null, r.purchased_at ?? null,
            r.checked_out_to ?? null, r.checked_out_at ?? null,
            r.due_back ?? null, r.checkout_destination ?? null,
            r.created_at ?? 0, r.modified_at ?? 0,
          ]
        );
      }
      console.log(`  items: ${rows.length} rows`);
    }

    // lists
    if (tableExists(sqlite, 'lists')) {
      const rows = tableRows(sqlite, 'lists');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO lists (id, user_id, name, description, qr_token, created_at, modified_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.user_id, r.name, r.description ?? '', r.qr_token, r.created_at ?? 0, r.modified_at ?? 0]
        );
      }
      console.log(`  lists: ${rows.length} rows`);
    }

    // list_shares
    if (tableExists(sqlite, 'list_shares')) {
      const rows = tableRows(sqlite, 'list_shares');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO list_shares (id, list_id, owner_id, shared_with_id, created_at)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.list_id, r.owner_id, r.shared_with_id, r.created_at ?? 0]
        );
      }
      console.log(`  list_shares: ${rows.length} rows`);
    }

    // list_items
    if (tableExists(sqlite, 'list_items')) {
      const rows = tableRows(sqlite, 'list_items');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO list_items (list_id, item_id) VALUES ($1,$2)
           ON CONFLICT (list_id, item_id) DO NOTHING`,
          [r.list_id, r.item_id]
        );
      }
      console.log(`  list_items: ${rows.length} rows`);
    }

    // documents
    if (tableExists(sqlite, 'documents')) {
      const rows = tableRows(sqlite, 'documents');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO documents (id, item_id, user_id, filename, mime_type, size, data, thumb_data, created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.item_id, r.user_id, r.filename, r.mime_type ?? '', r.size ?? 0, r.data, r.thumb_data ?? null, r.created_at ?? 0]
        );
      }
      console.log(`  documents: ${rows.length} rows`);
    }

    // checkouts
    if (tableExists(sqlite, 'checkouts')) {
      const rows = tableRows(sqlite, 'checkouts');
      for (const r of rows) {
        await pgClient.query(
          `INSERT INTO checkouts (id, item_id, user_id, borrower, destination, checked_out, due_back, checked_in, notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.item_id, r.user_id, r.borrower, r.destination ?? '', r.checked_out, r.due_back ?? null, r.checked_in ?? null, r.notes ?? '']
        );
      }
      console.log(`  checkouts: ${rows.length} rows`);
    }

    await pgClient.query('COMMIT');

    console.log('\n==> Resetting sequences...');
    for (const t of ['users', 'categories', 'locations', 'items', 'lists', 'list_shares', 'documents', 'checkouts']) {
      await resetSequence(t);
    }

    console.log('==> Migration complete!');
  } catch (err) {
    await pgClient.query('ROLLBACK');
    console.error('Migration failed, rolled back:', err.message);
    process.exit(1);
  } finally {
    pgClient.release();
    sqlite.close();
    await pgPool.end();
  }
}

main();
