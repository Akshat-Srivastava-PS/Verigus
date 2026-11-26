// Durable file-backed state store (production hardening).
//
// One JSON file (src/data/state.json) holds everything the guard must not
// lose on a restart: permanent blocks, reputation, the observe baseline,
// recent incidents, and pending cross-site intel findings. Writes are
// atomic (tmp file + rename) and debounced; a corrupt file is quarantined
// and the guard starts fresh rather than crashing.
//
// Honest limitation: on Render's free tier the filesystem is ephemeral —
// a redeploy still resets this file. The production step is a Render
// persistent disk mounted at src/data, or a DATABASE_URL Postgres adapter
// behind this same interface (see README "Production deploy").
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

class Store {
  constructor(statePath) {
    this.path = statePath || DEFAULT_STATE_PATH;
    this.data = this._load();
    this._saveTimer = null;
    this._dirty = false;
  }

  _load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.path, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('state file is not a JSON object');
      }
      const state = emptyState();
      if (parsed.blocks && typeof parsed.blocks === 'object') state.blocks = parsed.blocks;
      if (parsed.reputation && typeof parsed.reputation === 'object') state.reputation = parsed.reputation;
      if (parsed.baseline && typeof parsed.baseline === 'object') state.baseline = parsed.baseline;
      if (Array.isArray(parsed.incidents)) state.incidents = parsed.incidents.slice(0, 200);
      if (Array.isArray(parsed.intelPending)) state.intelPending = parsed.intelPending;
      if (typeof parsed.libraryVersion === 'number') state.libraryVersion = parsed.libraryVersion;
      return state;
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

  /** Immediate atomic save (tmp file + rename). */
  save() {
    const dir = path.dirname(this.path);
    try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
    const tmp = `${this.path}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.path);
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

  /** Flush any pending debounced save now (e.g. on block). */
  flush() {
    if (this._saveTimer) { clearTimeout(this._saveTimer); this._saveTimer = null; }
    if (this._dirty) {
      this._dirty = false;
      try { this.save(); } catch (_) {}
    }
  }
}

module.exports = { Store, DEFAULT_STATE_PATH, emptyState };
