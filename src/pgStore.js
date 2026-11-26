// Postgres backend for the durable store (option 2: free external database,
// e.g. Neon free tier). Active ONLY when DATABASE_URL is set — see
// Store.create() in store.js. When DATABASE_URL is unset, the store stays
// file-backed (src/data/state.json) and this module is never loaded.
//
// Design: one table, one row, whole state document as JSONB. This matches
// the store's existing single-JSON design (store.js holds the whole guard
// state in one document), so the store interface does not change and a
// write is a single atomic upsert — blocks, reputation, baseline,
// incidents and pending intel are never half-written. Per-entity tables
// would add migrations and joins for a six-field document the guard
// always reads and writes whole; see PRODUCTION-PLAN.md for the trade-off.
//
// No secrets live here: the connection string comes only from the
// environment (DATABASE_URL). It is never logged.
'use strict';

const STATE_KEY = 'guard-state';

const SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS verigus_state (
  key TEXT PRIMARY KEY,
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`;

const LOAD_SQL = 'SELECT state FROM verigus_state WHERE key = $1';

const SAVE_SQL = `INSERT INTO verigus_state (key, state) VALUES ($1, $2::jsonb)
  ON CONFLICT (key) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`;

/**
 * Decide TLS for a Postgres connection string. Neon requires TLS; its
 * connection strings carry sslmode=require. Plain local strings
 * (postgres://localhost/...) get no TLS. Never downgrades an explicit
 * sslmode=require, and never enables TLS for sslmode=disable.
 */
function sslOptionsFor(connectionString) {
  try {
    const u = new URL(String(connectionString));
    const mode = (u.searchParams.get('sslmode') || '').toLowerCase();
    if (mode === 'disable') return false;
    if (mode === 'require' || mode === 'verify-ca' || mode === 'verify-full') return true;
    if (u.hostname.endsWith('.neon.tech')) return true;
    return false;
  } catch (_) {
    return false;
  }
}

function createPool(connectionString) {
  // Lazy require so the module can be loaded (and unit-tested with a fake
  // pool) without the pg package present; the real path throws a clear
  // error if pg was never installed.
  let pg;
  try {
    pg = require('pg');
  } catch (_) {
    throw new Error("DATABASE_URL is set but the 'pg' package is not installed (run: npm install pg)");
  }
  return new pg.Pool({
    connectionString,
    ssl: sslOptionsFor(connectionString),
    max: 3, // the guard is a single process; it needs a handful of connections at most
    connectionTimeoutMillis: 5000, // fail fast at startup if the DB is unreachable
    idleTimeoutMillis: 30000,
  });
}

class PostgresBackend {
  // `key` is the row key (default 'guard-state'). Tests pass their own
  // key so a live-DB test can never touch the guard's real row.
  constructor(pool, key) {
    this.pool = pool;
    this.key = key || STATE_KEY;
    this.kind = 'postgres';
  }

  async ensureSchema() {
    await this.pool.query(SCHEMA_SQL);
  }

  /** Returns the raw stored state document, or null when no row exists. */
  async load() {
    const res = await this.pool.query(LOAD_SQL, [this.key]);
    if (!res || !Array.isArray(res.rows) || res.rows.length === 0) return null;
    const raw = res.rows[0].state;
    // pg returns JSONB as a parsed object already; tolerate a string too.
    if (typeof raw === 'string') {
      try { return JSON.parse(raw); } catch (_) { return null; }
    }
    return raw;
  }

  /** Atomic upsert of the whole state document (one row, one statement). */
  async save(state) {
    await this.pool.query(SAVE_SQL, [this.key, JSON.stringify(state)]);
  }

  async close() {
    if (this.pool && typeof this.pool.end === 'function') await this.pool.end();
  }
}

/**
 * Build a backend for a connection string. `poolFactory` is an injection
 * point for tests: (connectionString, ssl) => pool-like object with
 * query()/end(). When omitted, a real pg Pool is created. `key` overrides
 * the row key (tests only; the guard always uses 'guard-state').
 */
function createPostgresBackend(connectionString, poolFactory, key) {
  if (!connectionString) throw new Error('createPostgresBackend requires a connection string');
  const pool = poolFactory
    ? poolFactory(connectionString, sslOptionsFor(connectionString))
    : createPool(connectionString);
  return new PostgresBackend(pool, key);
}

module.exports = { PostgresBackend, createPostgresBackend, createPool, sslOptionsFor, STATE_KEY, SCHEMA_SQL, LOAD_SQL, SAVE_SQL };
