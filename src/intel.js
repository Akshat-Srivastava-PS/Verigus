// Cross-site threat-intelligence network (blueprint Phase 3).
//
// Every protected site's anonymised findings are filed back into the
// shared Threat Library and published in its daily update. This is the
// filing/ingest protocol + merge logic; a single-site deployment works
// standalone with zero peers — filings from this site alone still merge.
//
//   POST /v1/intel/report  { reporter_site, finding: { category, severity,
//     name, description, match: { pathPatterns?, sequence?,
//     contentPatterns?, minRequestsPerMin? }, source? } }
//   GET  /v1/intel/status  { pending, mergedTotal, lastMerge }
//
// Ingest validates the schema strictly and strips PII before storage
// (IPs, raw user-agents, cookies, user ids are dropped — only patterns
// travel). Merge runs inside the library's daily refresh: findings are
// de-duplicated by pattern hash, corroborated findings (same pattern from
// 2+ sites) are marked as such, and merged entries carry source
// "verigus-network" and bump the library version.
'use strict';

const crypto = require('crypto');

const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

function patternHash(finding) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(finding.match || {}) + '|' + (finding.name || ''))
    .digest('hex').slice(0, 16);
}

function stripPii(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  const DROP = new Set(['ip', 'ip_address', 'user_agent', 'useragent', 'cookie', 'cookies', 'user_id', 'userId', 'email', 'authorization', 'api_key', 'apikey']);
  for (const [k, v] of Object.entries(obj)) {
    if (DROP.has(k.toLowerCase())) continue;
    out[k] = (v && typeof v === 'object') ? stripPii(v) : v;
  }
  return out;
}

class IntelNetwork {
  constructor(store, library) {
    this.store = store || null;
    this.library = library || null;
    this.mergedTotal = 0;
    this.lastMerge = null;
  }

  get pending() {
    return (this.store && this.store.data && Array.isArray(this.store.data.intelPending))
      ? this.store.data.intelPending : [];
  }

  _save() {
    if (this.store) this.store.saveSoon();
  }

  /** Validate + anonymise + file one finding. Returns { accepted, id?, reason? }. */
  fileFinding(report) {
    if (!report || typeof report !== 'object') return { accepted: false, reason: 'report must be a JSON object' };
    const finding = report.finding;
    if (!finding || typeof finding !== 'object') return { accepted: false, reason: 'report.finding is required' };
    for (const f of ['category', 'severity', 'name', 'description']) {
      if (!finding[f] || typeof finding[f] !== 'string') return { accepted: false, reason: `finding.${f} is required (string)` };
    }
    if (!VALID_SEVERITIES.has(String(finding.severity).toLowerCase())) {
      return { accepted: false, reason: `severity must be one of ${[...VALID_SEVERITIES].join(', ')}` };
    }
    if (finding.match !== undefined && (typeof finding.match !== 'object' || Array.isArray(finding.match))) {
      return { accepted: false, reason: 'finding.match must be an object when present' };
    }
    const clean = stripPii(finding);
    clean.id = `intel-${patternHash(clean)}`;
    clean.source = 'verigus-network';
    clean.reporterSite = typeof report.reporter_site === 'string' ? report.reporter_site.slice(0, 120) : 'anonymous-site';
    clean.filedAt = new Date().toISOString();
    clean.corroborations = 1;
    const pending = this.pending;
    const existing = pending.find((p) => p.id === clean.id);
    if (existing) {
      existing.corroborations += 1;
      existing.lastSeenAt = clean.filedAt;
      this._save();
      return { accepted: true, id: clean.id, reason: 'corroborated an already-pending finding' };
    }
    if (this.library && this.library.entries.some((e) => e.id === clean.id)) {
      return { accepted: false, reason: 'finding already in the library' };
    }
    pending.push(clean);
    if (this.store) this.store.data.intelPending = pending;
    this._save();
    return { accepted: true, id: clean.id, reason: 'filed for the next daily merge' };
  }

  /** Merge pending findings into the library (called by the daily refresh). */
  mergePending() {
    const report = { merged: 0, duplicates: 0, rejected: 0 };
    if (!this.library) return report;
    const pending = this.pending;
    const remaining = [];
    for (const finding of pending) {
      if (this.library.entries.some((e) => e.id === finding.id)) { report.duplicates += 1; continue; }
      const entry = {
        id: finding.id,
        name: finding.name,
        category: finding.category,
        severity: String(finding.severity).toLowerCase(),
        description: finding.description,
        source: 'verigus-network',
        match: finding.match || {},
        corroborations: finding.corroborations || 1,
      };
      this.library.entries.push(entry);
      report.merged += 1;
    }
    if (this.store) this.store.data.intelPending = remaining;
    this.mergedTotal += report.merged;
    this.lastMerge = new Date().toISOString();
    this._save();
    return report;
  }

  status() {
    return {
      pending: this.pending.length,
      mergedTotal: this.mergedTotal,
      lastMerge: this.lastMerge,
    };
  }
}

module.exports = { IntelNetwork, patternHash, stripPii };
