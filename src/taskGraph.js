// Task Graph — links an agent's requests across endpoints and sessions
// into one task, and judges the task, not the single request.
// (Blueprint Module 2: Task Graph Engine.)
'use strict';

class Session {
  constructor(fingerprint) {
    this.fingerprint = fingerprint;
    this.requests = []; // { path, method, ts, dataClass }
    this.startedAt = Date.now();
  }

  add(req) {
    this.requests.push({ path: req.path, method: req.method, ts: Date.now(), dataClass: req.dataClass });
  }

  /** Requests in the trailing window (ms). Burst measure — velocity
   * scoring uses this, not the whole-session average, so a short burst
   * of 100 requests in 2 seconds reads as a burst, not as a slow crawl. */
  requestsInWindow(ms) {
    const cutoff = Date.now() - ms;
    let n = 0;
    for (let i = this.requests.length - 1; i >= 0; i -= 1) {
      if (this.requests[i].ts >= cutoff) n += 1;
      else break;
    }
    return n;
  }

  /** Effective pace (requests/min): total requests over the session span,
   * with a 30-second minimum span so a handful of requests in the first
   * second does not read as thousands per minute. */
  effectiveRpm() {
    if (this.requests.length < 2) return 0;
    const spanMs = Math.max(30000, this.requests[this.requests.length - 1].ts - this.requests[0].ts);
    return (this.requests.length / spanMs) * 60000;
  }

  requestsPerMin() {
    return this.effectiveRpm();
  }

  /** Distinct endpoints touched, in first-seen order. */
  endpointSequence() {
    const seen = [];
    for (const r of this.requests) {
      if (!seen.includes(r.path)) seen.push(r.path);
    }
    return seen;
  }

  /**
   * Task-shape classification from the observed sequence.
   * Returns one of: browsing, price-check, traversal, enumeration,
   * credential-probing, sensitive-hunting, transaction-chain, unknown.
   */
  taskShape() {
    const paths = this.requests.map((r) => r.path);
    const has = (re) => paths.some((p) => re.test(p));
    const sensitive = paths.filter((p) => /^\/(\.env|\.git|config|backup|admin)/.test(p)).length;
    const auth = paths.filter((p) => /^\/login|^\/account\/reset/.test(p)).length;
    const catalog = paths.filter((p) => /^\/products/.test(p)).length;

    if (sensitive > 0) return 'sensitive-hunting';
    if (auth >= 3) return 'credential-probing';
    if (catalog >= 10 && this.effectiveRpm() > 60) return 'traversal';
    if (paths.length >= 8 && new Set(paths).size >= 8) return 'enumeration';
    if (has(/^\/api\/v1\/orders/) && has(/^\/account/)) return 'transaction-chain';
    if (catalog > 0 && this.effectiveRpm() <= 60) return 'price-check';
    if (paths.length > 0) return 'browsing';
    return 'unknown';
  }

  /**
   * Goal drift: does the observed task still match the declared purpose?
   * Returns true when the task shape falls outside the purpose's shape.
   */
  static driftsFromPurpose(taskShape, purpose) {
    const allowed = {
      'price comparison': ['price-check', 'browsing'],
      'product research': ['price-check', 'browsing', 'enumeration'],
      'order-status lookup': ['transaction-chain', 'browsing'],
      'search indexing': ['traversal', 'price-check', 'browsing'],
    };
    const ok = allowed[purpose];
    if (!ok) return true; // unrecognised purpose: any focused task is drift
    return !ok.includes(taskShape);
  }
}

module.exports = { Session };
