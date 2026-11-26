// Structured logging + audit log + SIEM forwarding.
//
// Every guard event is a JSON line on stdout (structured logging) and an
// entry in the append-only audit log (src/data/audit.jsonl, rotated once
// past 5 MB). Block/incident events are also forwarded to a SIEM webhook
// when SIEM_WEBHOOK_URL is set (fire-and-forget; a failed forward is
// logged, never fatal). When SIEM_WEBHOOK_SECRET is set, forwards carry
// an HMAC-SHA256 signature header (X-Verigus-Signature) over the body.
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const AUDIT_PATH = path.join(__dirname, 'data', 'audit.jsonl');
const MAX_AUDIT_BYTES = 5 * 1024 * 1024;

/** One structured JSON log line to stdout. */
function log(level, event, fields) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, event, ...(fields || {}) });
  console.log(line);
  return line;
}

class AuditLog {
  constructor(auditPath) {
    this.path = auditPath || AUDIT_PATH;
    this.siemUrl = process.env.SIEM_WEBHOOK_URL || null;
    this.siemSecret = process.env.SIEM_WEBHOOK_SECRET || null;
  }

  record(event, fields) {
    const entry = { ts: new Date().toISOString(), event, ...(fields || {}) };
    try {
      fs.mkdirSync(path.dirname(this.path), { recursive: true });
      try {
        if (fs.statSync(this.path).size > MAX_AUDIT_BYTES) {
          fs.renameSync(this.path, `${this.path}.1`);
        }
      } catch (_) { /* file does not exist yet */ }
      fs.appendFileSync(this.path, JSON.stringify(entry) + '\n');
    } catch (_) { /* the audit log must never break the guard */ }
    this._forwardSiem(entry);
    return entry;
  }

  /** Last N audit entries (newest first). Returns [] when the log is absent. */
  readAll(limit) {
    try {
      const lines = fs.readFileSync(this.path, 'utf8').split('\n').filter(Boolean);
      const entries = lines.map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);
      return entries.slice(-(limit || 200)).reverse();
    } catch (_) {
      return [];
    }
  }

  _forwardSiem(entry) {
    if (!this.siemUrl) return;
    let url;
    try { url = new URL(this.siemUrl); } catch (_) { return; }
    const body = JSON.stringify(entry);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
    if (this.siemSecret) {
      headers['X-Verigus-Signature'] = crypto.createHmac('sha256', this.siemSecret).update(body).digest('hex');
    }
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method: 'POST', headers, timeout: 5000 }, (res) => { res.resume(); });
    req.on('timeout', () => req.destroy(new Error('SIEM webhook timed out')));
    req.on('error', (err) => log('warn', 'siem_forward_failed', { error: String(err.message || err) }));
    req.end(body);
  }
}

module.exports = { log, AuditLog, AUDIT_PATH, MAX_AUDIT_BYTES };
