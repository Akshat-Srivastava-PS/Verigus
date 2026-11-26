// Tests for the Postgres persistence adapter (DATABASE_URL / Neon free
// tier). The adapter logic is covered with an in-memory fake of the pg
// Pool interface, so `npm test` passes with no live Postgres available.
// The one live-DB test at the bottom runs only when DATABASE_URL is set
// AND reachable, and it uses its own row key ('guard-state-test') so it
// can never touch the guard's real state.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Store, emptyState } = require('../src/store');
const { PostgresBackend, createPostgresBackend, sslOptionsFor, STATE_KEY, SCHEMA_SQL, SAVE_SQL } = require('../src/pgStore');

// --- Fake pg Pool: an in-memory verigus_state table --------------------------

class FakePool {
  constructor() {
    this.rows = new Map(); // key -> parsed state document
    this.queries = []; // { text, params }
    this.ended = false;
    this.failNext = null;
  }

  async query(text, params) {
    this.queries.push({ text, params: params || [] });
    if (this.failNext) {
      const err = this.failNext;
      this.failNext = null;
      throw err;
    }
    const flat = String(text).replace(/\s+/g, ' ');
    if (/CREATE TABLE IF NOT EXISTS verigus_state/.test(flat)) return { rows: [], rowCount: 0 };
    if (/SELECT state FROM verigus_state WHERE key = \$1/.test(flat)) {
      const row = this.rows.get((params || [])[0]);
      return { rows: row ? [{ state: row }] : [], rowCount: row ? 1 : 0 };
    }
    if (/INSERT INTO verigus_state/.test(flat)) {
      this.rows.set(params[0], JSON.parse(params[1]));
      return { rows: [], rowCount: 1 };
    }
    if (/DELETE FROM verigus_state WHERE key = \$1/.test(flat)) {
      this.rows.delete(params[0]);
      return { rows: [], rowCount: 1 };
    }
    throw new Error(`FakePool: unexpected query: ${text}`);
  }

  async end() { this.ended = true; }
}

function fakePoolFactory(pool) {
  return () => pool;
}

function scratchDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'verigus-pg-test-'));
}

function richState() {
  const s = emptyState();
  s.blocks = { fp1: { id: 'dossier-1', operator: 'ProbeTool', risk: 94 } };
  s.reputation = { ShopBot: { score: 25, purposeMismatches: [{ at: '2026-11-26T00:00:00.000Z' }] } };
  s.baseline = { requestsSeen: 571, distinctAgents: 21, ready: true, confidence: 0.71 };
  s.incidents = [{ at: '2026-11-26T00:00:00.000Z', kind: 'BLOCK', summary: 'blocked fp1' }];
  s.intelPending = [{ id: 'f-1', category: 'scraping' }];
  s.libraryVersion = 3;
  return s;
}

// --- SSL / connection handling ------------------------------------------------

test('sslOptionsFor enables TLS for Neon / sslmode=require and not for plain URLs', () => {
  assert.equal(sslOptionsFor('postgres://user:pass@ep-xyz.us-east-2.aws.neon.tech/db?sslmode=require'), true, 'Neon sslmode=require -> TLS');
  assert.equal(sslOptionsFor('postgres://user:pass@ep-xyz.us-east-2.aws.neon.tech/db'), true, 'Neon host -> TLS even without sslmode');
  assert.equal(sslOptionsFor('postgres://user:pass@localhost:5432/verigus'), false, 'localhost -> no TLS');
  assert.equal(sslOptionsFor('postgres://user:pass@db.example/db?sslmode=disable'), false, 'explicit sslmode=disable -> no TLS');
  assert.equal(sslOptionsFor('not a url'), false, 'garbage URL -> no TLS, no throw');
});

test('createPostgresBackend passes the connection string and TLS flag to the pool factory', () => {
  let captured = null;
  const backend = createPostgresBackend('postgres://u:p@ep-x.neon.tech/db?sslmode=require', (cs, ssl) => {
    captured = { cs, ssl };
    return new FakePool();
  });
  assert.equal(backend.kind, 'postgres');
  assert.equal(captured.cs, 'postgres://u:p@ep-x.neon.tech/db?sslmode=require');
  assert.equal(captured.ssl, true, 'Neon URL reaches the pool with TLS on');
});

// --- Schema + SQL ----------------------------------------------------------------

test('ensureSchema creates the verigus_state table with a JSONB state column', async () => {
  const pool = new FakePool();
  const backend = new PostgresBackend(pool);
  await backend.ensureSchema();
  assert.equal(pool.queries.length, 1, 'one statement');
  assert.match(pool.queries[0].text, /CREATE TABLE IF NOT EXISTS verigus_state/);
  assert.match(pool.queries[0].text, /state JSONB NOT NULL/);
  assert.match(pool.queries[0].text, /key TEXT PRIMARY KEY/);
  assert.equal(SCHEMA_SQL, pool.queries[0].text, 'the issued SQL is the exported schema');
});

test('save upserts atomically (ON CONFLICT) and load returns the stored document', async () => {
  const pool = new FakePool();
  const backend = new PostgresBackend(pool);
  assert.equal(await backend.load(), null, 'empty table loads as null');
  const state = richState();
  await backend.save(state);
  const upsert = pool.queries.find((q) => /INSERT INTO verigus_state/.test(q.text));
  assert.ok(upsert, 'an INSERT ran');
  assert.match(upsert.text, /ON CONFLICT \(key\) DO UPDATE/, 'upsert is atomic');
  assert.equal(upsert.params[0], STATE_KEY, 'single row key');
  assert.equal(typeof upsert.params[1], 'string', 'state is serialized to JSON for JSONB');
  assert.equal(SAVE_SQL, upsert.text, 'the issued SQL is the exported upsert');
  // A second save overwrites the same row (upsert), it does not add one.
  const changed = richState();
  changed.blocks = { fp2: { id: 'dossier-2' } };
  await backend.save(changed);
  assert.equal(pool.rows.size, 1, 'still one row after a second save');
  assert.deepEqual(await backend.load(), changed, 'load returns the latest document');
});

// --- Store.create over Postgres ---------------------------------------------------

test('Store.create with a Postgres backend round-trips the whole guard state across a restart', async () => {
  const pool = new FakePool();
  const factory = fakePoolFactory(pool);
  const dir = scratchDir();
  const s1 = await Store.create({ databaseUrl: 'postgres://fake/db', statePath: path.join(dir, 'state.json'), poolFactory: factory });
  assert.equal(s1.backendKind, 'postgres', 'Postgres backend is active');
  assert.equal(s1.seededFromFile, false, 'no seed: the scratch file does not exist');
  const state = richState();
  s1.data.blocks = state.blocks;
  s1.data.reputation = state.reputation;
  s1.data.baseline = state.baseline;
  s1.data.incidents = state.incidents;
  s1.data.intelPending = state.intelPending;
  s1.data.libraryVersion = state.libraryVersion;
  await s1.flush();
  await s1.close();
  assert.equal(pool.ended, true, 'close() ends the pool');

  // Restart against the same database: everything comes back exactly.
  const pool2 = new FakePool();
  pool2.rows = pool.rows; // same database, new connection
  const s2 = await Store.create({ databaseUrl: 'postgres://fake/db', statePath: path.join(dir, 'state.json'), poolFactory: fakePoolFactory(pool2) });
  assert.deepEqual(s2.data.blocks, state.blocks, 'blocks survive a restart');
  assert.deepEqual(s2.data.reputation, state.reputation, 'reputation survives a restart');
  assert.deepEqual(s2.data.baseline, state.baseline, 'baseline survives a restart');
  assert.deepEqual(s2.data.incidents, state.incidents, 'incidents survive a restart');
  assert.deepEqual(s2.data.intelPending, state.intelPending, 'pending intel survives a restart');
  assert.equal(s2.data.libraryVersion, 3, 'library version survives a restart');
  await s2.close();
});

test('Store.create seeds Postgres from the local file when the table is empty', async () => {
  const dir = scratchDir();
  const filePath = path.join(dir, 'state.json');
  const fileState = richState();
  fs.writeFileSync(filePath, JSON.stringify(fileState, null, 2));
  const pool = new FakePool();
  const s1 = await Store.create({ databaseUrl: 'postgres://fake/db', statePath: filePath, poolFactory: fakePoolFactory(pool) });
  assert.equal(s1.seededFromFile, true, 'seed is reported');
  assert.deepEqual(s1.data.blocks, fileState.blocks, 'seeded blocks load into the store');
  assert.deepEqual(pool.rows.get(STATE_KEY), fileState, 'the file state was written to Postgres');
  await s1.close();

  // A later boot reads Postgres, not the file: change the file, state stays.
  const changed = richState();
  changed.blocks = { fp9: { id: 'dossier-9' } };
  fs.writeFileSync(filePath, JSON.stringify(changed, null, 2));
  const s2 = await Store.create({ databaseUrl: 'postgres://fake/db', statePath: filePath, poolFactory: fakePoolFactory(pool) });
  assert.equal(s2.seededFromFile, false, 'no second seed once Postgres has the state');
  assert.deepEqual(s2.data.blocks, fileState.blocks, 'Postgres wins over the file after seeding');
  await s2.close();
});

test('Store.create without DATABASE_URL stays file-backed, exactly as before', async () => {
  const saved = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    const dir = scratchDir();
    const p = path.join(dir, 'state.json');
    const s1 = await Store.create({ statePath: p });
    assert.equal(s1.backendKind, 'file', 'no DATABASE_URL -> file backend');
    s1.data.blocks = { fp1: { id: 'dossier-1' } };
    s1.save();
    const s2 = new Store(p);
    assert.deepEqual(s2.data.blocks, { fp1: { id: 'dossier-1' } }, 'file round-trip unchanged');
  } finally {
    if (saved === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = saved;
  }
});

test('Store.create fails fast with a clear error when Postgres is unreachable', async () => {
  const pool = new FakePool();
  const err = new Error('connect ECONNREFUSED 127.0.0.1:5432');
  err.code = 'ECONNREFUSED';
  pool.failNext = err;
  await assert.rejects(
    Store.create({ databaseUrl: 'postgres://fake/db', poolFactory: fakePoolFactory(pool) }),
    /Postgres store unreachable/,
    'unreachable DB rejects instead of starting with amnesia'
  );
});

test('debounced saves coalesce: two saveSoon() calls produce one Postgres write', async () => {
  const pool = new FakePool();
  const dir = scratchDir();
  const s = await Store.create({ databaseUrl: 'postgres://fake/db', statePath: path.join(dir, 'state.json'), poolFactory: fakePoolFactory(pool) });
  assert.equal(s.seededFromFile, false, 'no seed: the scratch file does not exist');
  s.data.blocks = { fp1: { id: 'dossier-1' } };
  s.saveSoon();
  s.saveSoon();
  await s.flush(); // flush cancels the timer and writes once, now
  const inserts = pool.queries.filter((q) => /INSERT INTO verigus_state/.test(q.text));
  assert.equal(inserts.length, 1, 'one upsert for the coalesced mutations');
  await s.close();
});

// --- Live database (only when DATABASE_URL is set and reachable) -------------------
// Uses its own row key ('guard-state-test') and deletes it afterwards, so it
// can never touch the guard's real state. Skips gracefully otherwise.

test('live Postgres round-trip (skipped when no DATABASE_URL is reachable)', async (t) => {
  const url = process.env.DATABASE_URL;
  if (!url) {
    t.skip('no DATABASE_URL set — live Postgres test skipped');
    return;
  }
  const TEST_KEY = 'guard-state-test';
  let backend;
  try {
    backend = createPostgresBackend(url, undefined, TEST_KEY);
    await backend.ensureSchema();
    await backend.load(); // throws if unreachable
  } catch (err) {
    t.skip(`Postgres unreachable (${err.message}) — live Postgres test skipped`);
    return;
  }
  try {
    const state = richState();
    await backend.save(state);
    const loaded = await backend.load();
    assert.deepEqual(loaded.blocks, state.blocks, 'blocks round-trip against real Postgres');
    assert.deepEqual(loaded.baseline, state.baseline, 'baseline round-trips against real Postgres');
    assert.equal(loaded.libraryVersion, 3);
  } finally {
    await backend.pool.query('DELETE FROM verigus_state WHERE key = $1', [TEST_KEY]);
    await backend.close();
  }
});
