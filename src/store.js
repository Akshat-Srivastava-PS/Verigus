// Durable state store (production hardening).
//
// One JSON document holds everything the guard must not lose on a restart:
// permanent blocks, reputation, the observe baseline, recent incidents,
// and pending cross-site intel findings.
//
// Two backends, one interface:
//   - File (default): src/data/state.json, atomic tmp+rename writes, a
//     corrupt file is quarantined and the guard starts fresh.
//   - Postgres (when DATABASE_URL is set): one table, one row, the whole
//     document as JSONB with atomic upserts (see pgStore.js). Load happens
//     at startup before serving; a restart against the same database
//     restores blocks, dossiers, reputation and baseline exactly.
//
// Honest limitation (file backend only): on Render's free tier the
// filesystem is ephemeral — a redeploy resets the file. Set DATABASE_URL
// (e.g. a free Neon Postgres project) and the state survives redeploys.
// The legacy blocks.json is migrated in on first load.
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_STATE_PATH = path.join(__dirname, 'data', 'state.json');

function emptyState() {
  return {
    blocks: {}, // fingerprint -> dossier (PERMANENT)
    reputation: {}, // identity -> reputation record
    baseline: null, // serialized Baseline or null
    incidents: [], // newest first, capped
    intelPending: [], // cross-site findings awaiting the daily merge
    libraryVersion: null,
  };
}

/** Shape-check a parsed state document. Total: never throws, returns a
 *  clean state (empty sections for anything missing or malformed). Shared
 *  by the file loader and the Postgres loader so both backends agree on
 *  what a valid state looks like. */
function normalizeState(parsed) {
  const state = emptyState();
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return state;
  if (parsed.blocks && typeof parsed.blocks === 'object' && !Array.isArray(parsed.blocks)) state.blocks = parsed.blocks;
  if (parsed.reputation && typeof parsed.reputation === 'object' && !Array.isArray(parsed.reputation)) state.reputation = parsed.reputation;
  if (parsed.baseline && typeof parsed.baseline === 'object' && !Array.isArray(parsed.baseline)) state.baseline = parsed.baseline;
  if (Array.isArray(parsed.incidents)) state.incidents = parsed.incidents.slice(0, 200);
  if (Array.isArray(parsed.intelPending)) state.intelPending = parsed.intelPending;
  if (typeof parsed.libraryVersion === 'number') state.libraryVersion = parsed.libraryVersion;
  return state;
}

function hasContent(state) {
  if (!state) return false;
  return Object.keys(state.blocks || {}).length > 0
    || Object.keys(state.reputation || {}).length > 0
    || state.baseline !== null
    || (Array.isArray(state.incidents) && state.incidents.length > 0)
    || (Array.isArray(state.intelPending) && state.intelPending.length > 0);
}

class Store {
  /**
   * Synchronous file-backed store. `options` is for Store.create() only:
   * { backend } attaches a PostgresBackend and { data } supplies the
   * already-loaded state instead of reading the file. Direct callers
   * (tests, local dev) keep using `new Store(path)` unchanged.
   */
  constructor(statePath, options) {
    const opts = options || {};
    this.path = statePath || DEFAULT_STATE_PATH;
    this.backend = opts.backend || null;
    this.backendKind = this.backend ? 'postgres' : 'file';
    this.seededFromFile = !!opts.seededFromFile;
    this.data = opts.data ? normalizeState(opts.data) : this._load();
    this._saveTimer = null;
    this._dirty = false;
    // Serialized write chain for the Postgres backend: every upsert waits
    // for the previous one, so a debounced save can never overtake a flush
    // and lose a block.
    this._pgChain = Promise.resolve();
  }

  /**
   * Async factory — the only entry point the server uses. Picks the
   * backend from the environment:
   *   - DATABASE_URL set: Postgres (pgStore.js). Connects, creates the
   *     table, loads the state. If the table is empty and a local state
   *     file exists with content, seeds Postgres from that file so a
   *     live guard's learned state carries over. Throws (fail fast) if
   *     the database is unreachable — serving with amnesia while
   *     believing state is durable would silently un-block agents.
   *   - DATABASE_URL unset: plain file-backed store, exactly as before.
   * `options` (tests only): { databaseUrl, statePath, poolFactory }.
   */
  static async create(options) {
    const opts = options || {};
    const databaseUrl = opts.databaseUrl || process.env.DATABASE_URL || '';
    if (!databaseUrl) return new Store(opts.statePath);
    let createPostgresBackend;
    try {
      ({ createPostgresBackend } = require('./pgStore'));
    } catch (err) {
      throw new Error(`DATABASE_URL is set but the Postgres adapter could not load: ${err.message}`);
    }
    const backend = createPostgresBackend(databaseUrl, opts.poolFactory);
    try {
      await backend.ensureSchema();
    } catch (err) {
      throw new Error(`Postgres store unreachable (DATABASE_URL): ${err.message}`);
    }
    let data = null;
    try {
      data = await backend.load();
    } catch (err) {
      throw new Error(`Postgres store read failed (DATABASE_URL): ${err.message}`);
    }
    let seededFromFile = false;
    if (!data) {
      // First boot against an empty database: carry the local file's
      // learned state over instead of starting from zero.
      const fileStore = new Store(opts.statePath);
      if (hasContent(fileStore.data)) {
        data = fileStore.data;
        try {
          await backend.save(data);
        } catch (err) {
          throw new Error(`Postgres store seed failed (DATABASE_URL): ${err.message}`);
        }
        seededFromFile = true;
      }
    }
    return new Store(opts.statePath, { backend, data: data || emptyState(), seededFromFile });
  }

  _load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.path, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('state file is not a JSON object');
      }
      return normalizeState(parsed);
    } catch (err) {
      if (err && err.code === 'ENOENT') {
        // First boot — migrate the legacy blocks.json if one exists.
        const state = emptyState();
        try {
          const legacy = JSON.parse(fs.readFileSync(path.join(path.dirname(this.path), 'blocks.json'), 'utf8'));
          if (legacy && typeof legacy === 'object') state.blocks = legacy;
        } catch (_) { /* no legacy blocks */ }
        return state;
      }
      // Corrupt file: quarantine it and start fresh — never crash the guard.
      try { fs.renameSync(this.path, `${this.path}.corrupt-${Date.now()}`); } catch (_) {}
      return emptyState();
    }
  }

  /** Immediate save. File: atomic tmp+rename (sync, as before).
   *  Postgres: atomic upsert, serialized behind earlier writes; returns a
   *  promise the caller may await (sync callers just fire and forget —
   *  the query is in flight before save() returns). */
  save() {
    if (!this.backend) {
      const dir = path.dirname(this.path);
      try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
      const tmp = `${this.path}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
      fs.renameSync(tmp, this.path);
      return undefined;
    }
    return this._enqueuePgSave();
  }

  _enqueuePgSave() {
    this._pgChain = this._pgChain
      .then(() => this.backend.save(this.data))
      .catch((err) => {
        // Never crash the guard on a failed write, and never swallow it
        // silently: the failure is logged and the in-memory state (the
        // guard's live view) is unaffected. The next save retries.
        // The connection string is never printed here.
        console.error('[verigus] postgres store save failed:', err && err.message ? err.message : err);
      });
    return this._pgChain;
  }

  /** Debounced save: coalesces rapid mutations into at most one write per 2s. */
  saveSoon() {
    this._dirty = true;
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      if (this._dirty) {
        this._dirty = false;
        try { this.save(); } catch (_) { /* state stays in memory if disk write fails */ }
      }
    }, 2000);
    if (this._saveTimer.unref) this._saveTimer.unref();
  }

  /** Flush any pending debounced save now (e.g. on block). File: sync.
   *  Postgres: initiates the upsert immediately and returns a promise
   *  that resolves when the write lands. */
  flush() {
    if (this._saveTimer) { clearTimeout(this._saveTimer); this._saveTimer = null; }
    if (!this.backend) {
      if (this._dirty) {
        this._dirty = false;
        try { this.save(); } catch (_) {}
      }
      return undefined;
    }
    this._dirty = false;
    return this._enqueuePgSave();
  }

  /** Graceful shutdown: flush pending writes, then close the backend.
   *  File backend: no-op. */
  async close() {
    if (this._saveTimer) { clearTimeout(this._saveTimer); this._saveTimer = null; }
    const pending = this.flush();
    if (pending) await pending;
    if (this.backend) await this.backend.close();
  }
}

module.exports = { Store, DEFAULT_STATE_PATH, emptyState, normalizeState };
