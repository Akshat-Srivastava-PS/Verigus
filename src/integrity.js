// Data-integrity watch (blueprint Phase 3): poisoning and disguised
// exfiltration detection.
//
// Two jobs:
//   1. Poisoning: the guard keeps SHA-256 hashes of the site content it
//      protects (product catalog, pricing). It re-hashes on a schedule and
//      on demand; a change nobody approved is a poisoning signal — an
//      attacker (or a compromised agent) planting instructions or false
//      data where other agents will read it. The watch also scans content
//      for injected instructions (see injection.js) and records poisoned
//      snippets so the guard can flag agents that echo them.
//   2. Disguised exfiltration: payloads leaving through benign-looking
//      channels — large base64/hex blobs in query strings or bodies,
//      and high volumes of sensitive-field reads. Flagged as findings
//      that feed the score.
'use strict';

const crypto = require('crypto');
const injection = require('./injection');

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

class IntegrityWatch {
  constructor() {
    this.contentHashes = new Map(); // contentId -> { hash, text }
    this.poisonedSnippets = []; // { source, snippet, at }
    this.findings = []; // newest first, capped
    this.lastCheckedAt = null;
  }

  /** Register site content the guard protects (id -> text). */
  registerContent(id, text) {
    const t = String(text == null ? '' : text);
    this.contentHashes.set(id, { hash: sha256(t), text: t });
    this._scanContentForInjection(id, t);
  }

  /** Re-hash registered content; report ids whose hash changed. */
  checkContent(currentTexts) {
    const changed = [];
    for (const [id, record] of this.contentHashes.entries()) {
      if (!currentTexts || !(id in currentTexts)) continue;
      const now = sha256(String(currentTexts[id]));
      if (now !== record.hash) {
        changed.push({ id, at: new Date().toISOString() });
        this.findings.unshift({ at: new Date().toISOString(), kind: 'content-changed', id, detail: `Content "${id}" changed without an approved update — possible poisoning.` });
        // Scan the NEW text for injected instructions: this is what feeds
        // the indirect/echo detection (a request quoting this content is
        // an echo attack). Scanning only at registration would never see
        // content poisoned after start.
        this._scanContentForInjection(id, String(currentTexts[id]));
      }
    }
    if (this.findings.length > 100) this.findings.length = 100;
    this.lastCheckedAt = new Date().toISOString();
    return changed;
  }

  _scanContentForInjection(id, text) {
    const hits = injection.scanText(text);
    for (const h of hits) {
      this.poisonedSnippets.push({ source: id, snippet: h.excerpt, pattern: h.pattern, at: new Date().toISOString() });
    }
    if (this.poisonedSnippets.length > 50) this.poisonedSnippets.length = 50;
  }

  /** Scan a piece of agent-supplied text for disguised exfiltration shapes. */
  static exfiltrationSignals(text) {
    if (!text || typeof text !== 'string') return [];
    const signals = [];
    // Long base64 blobs (encoded payloads smuggled in a query/body).
    const b64 = text.match(/[A-Za-z0-9+/]{100,}={0,2}/g) || [];
    for (const blob of b64) {
      if (blob.length >= 200) signals.push({ kind: 'base64-blob', detail: `base64 payload of ${blob.length} chars in request input` });
    }
    // Long hex blobs.
    const hex = text.match(/\b[0-9a-f]{128,}\b/gi) || [];
    for (const blob of hex) signals.push({ kind: 'hex-blob', detail: `hex payload of ${blob.length} chars in request input` });
    // Sensitive-field names carried out in bulk.
    const sensitiveFields = (text.match(/(password|secret|api[_-]?key|token|ssn|credit[_-]?card)/gi) || []).length;
    if (sensitiveFields >= 3) signals.push({ kind: 'sensitive-field-volume', detail: `${sensitiveFields} sensitive field names in one request` });
    return signals;
  }

  status() {
    return {
      contentRegistered: this.contentHashes.size,
      poisonedSnippets: this.poisonedSnippets.length,
      findings: this.findings.slice(0, 20),
      lastCheckedAt: this.lastCheckedAt,
    };
  }
}

module.exports = { IntegrityWatch, sha256 };
