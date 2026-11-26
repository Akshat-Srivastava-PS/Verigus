// Observe mode + readiness ETA (blueprint Section 07).
//
// Right after install the guard starts in OBSERVE mode by default: it
// learns what is normal for this site before ever blocking anything.
// How long observe lasts is the GUARD's own decision — no fixed period.
// It keeps the customer updated with a live ETA, shown in the dashboard
// and sent as a notification.
//
// Readiness is confidence-based: enough requests observed, enough distinct
// agents seen, and stable patterns (endpoint mix stops shifting). The ETA
// is estimated from the current observation rate.
'use strict';

const config = require('./config');

const READINESS_NOTIFICATION =
  "Your guard has learned your site's normal traffic and is now actively protecting you. It is ready — and will start enforcing from now.";

class Baseline {
  constructor() {
    this.requestsSeen = 0;
    this.agentsSeen = new Set();
    this.endpointCounts = new Map();
    this.endpointHistory = []; // endpoint per observed request, in order (capped)
    this.agentPaceSamples = []; // requests/min samples per agent session
    this.startedAt = Date.now();
    this.ready = false;
    this.readyAt = null;
    this.frozenPaceP95 = null; // velocity baseline frozen at readiness
    this.etaMinutes = null;
    this.notifications = []; // { at, kind, text } — dashboard + notification log
    this.lastEtaNotifiedAt = 0;
  }

  observe(agentFingerprint, path, requestsPerMin) {
    this.requestsSeen += 1;
    this.agentsSeen.add(agentFingerprint);
    this.endpointCounts.set(path, (this.endpointCounts.get(path) || 0) + 1);
    this.endpointHistory.push(path);
    if (this.endpointHistory.length > 2000) this.endpointHistory.shift();
    if (requestsPerMin > 0) {
      this.agentPaceSamples.push(requestsPerMin);
      if (this.agentPaceSamples.length > 500) this.agentPaceSamples.shift();
    }
    this._updateEta();
  }

  /** p95 of observed agent pace (requests/min) — the velocity baseline.
   * Frozen the moment the guard becomes ready, so enforcement is always
   * measured against what "normal" meant when learning finished, not a
   * baseline that keeps drifting under attack traffic. */
  agentPaceP95() {
    if (this.frozenPaceP95 !== null) return this.frozenPaceP95;
    if (this.agentPaceSamples.length === 0) return 0;
    const sorted = [...this.agentPaceSamples].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length * 0.95)] || sorted[sorted.length - 1];
  }

  /** Confidence 0-1 that the baseline is solid enough to enforce. */
  confidence() {
    const reqPart = Math.min(1, this.requestsSeen / config.baseline.targetRequests);
    const agentPart = Math.min(1, this.agentsSeen.size / config.baseline.minAgents);
    const stability = this._patternStability();
    return Math.min(1, reqPart * 0.5 + agentPart * 0.2 + stability * 0.3);
  }

  // Stability: how settled the endpoint mix is (1 = fully stable).
  // Total-variation distance between the endpoint distributions of the
  // first and second halves of the observed history: a site whose mix
  // has stopped shifting scores near 1; a site still discovering new
  // endpoints scores near 0. (A single dominant endpoint is stable by
  // this measure — correctly, since its mix is not shifting.)
  _patternStability() {
    const n = this.endpointHistory.length;
    if (n < 50) return 0;
    const half = Math.floor(n / 2);
    const dist = (slice) => {
      const counts = new Map();
      for (const p of slice) counts.set(p, (counts.get(p) || 0) + 1);
      const total = slice.length;
      for (const [k, v] of counts) counts.set(k, v / total);
      return counts;
    };
    const first = dist(this.endpointHistory.slice(0, half));
    const second = dist(this.endpointHistory.slice(half));
    const keys = new Set([...first.keys(), ...second.keys()]);
    let tvd = 0;
    for (const k of keys) tvd += Math.abs((first.get(k) || 0) - (second.get(k) || 0));
    return Math.max(0, 1 - tvd / 2);
  }

  _updateEta() {
    if (this.ready) {
      this.etaMinutes = 0;
      return;
    }
    const remaining = Math.max(0, config.baseline.targetRequests - this.requestsSeen);
    const elapsedMin = Math.max(1 / 60, (Date.now() - this.startedAt) / 60000);
    const rate = this.requestsSeen / elapsedMin; // requests per minute observed
    this.etaMinutes = rate > 0 ? Math.ceil(remaining / rate) : null;
  }

  /** Check readiness; on transition, emit the readiness notification. */
  checkReady() {
    if (this.ready) return false;
    const minSample = this.requestsSeen >= config.baseline.minRequests
      && this.agentsSeen.size >= config.baseline.minAgents;
    if (minSample && this.confidence() >= 0.8) {
      this.ready = true;
      this.readyAt = Date.now();
      this.frozenPaceP95 = this.agentPaceP95();
      this.etaMinutes = 0;
      this._notify('readiness', READINESS_NOTIFICATION);
      return true;
    }
    // ETA change notifications (material changes only, at most hourly).
    if (this.etaMinutes !== null && Date.now() - this.lastEtaNotifiedAt > 60 * 60 * 1000) {
      this.lastEtaNotifiedAt = Date.now();
      this._notify('eta', `Your guard is still learning your site's normal traffic — ready to enforce in ~${this.etaMinutes} min at the current pace.`);
    }
    return false;
  }

  _notify(kind, text) {
    this.notifications.push({ at: new Date().toISOString(), kind, text });
  }

  /** Serialize the baseline for the durable store (survives restarts). */
  serialize() {
    return {
      requestsSeen: this.requestsSeen,
      agentsSeen: [...this.agentsSeen],
      endpointCounts: [...this.endpointCounts.entries()],
      endpointHistory: this.endpointHistory.slice(-2000),
      agentPaceSamples: this.agentPaceSamples.slice(-500),
      startedAt: this.startedAt,
      ready: this.ready,
      readyAt: this.readyAt,
      frozenPaceP95: this.frozenPaceP95,
      etaMinutes: this.etaMinutes,
      notifications: this.notifications.slice(-10),
      lastEtaNotifiedAt: this.lastEtaNotifiedAt,
    };
  }

  /** Restore a serialized baseline (from the durable store). */
  restore(data) {
    if (!data || typeof data !== 'object') return;
    this.requestsSeen = data.requestsSeen || 0;
    this.agentsSeen = new Set(Array.isArray(data.agentsSeen) ? data.agentsSeen : []);
    this.endpointCounts = new Map(Array.isArray(data.endpointCounts) ? data.endpointCounts : []);
    this.endpointHistory = Array.isArray(data.endpointHistory) ? data.endpointHistory : [];
    this.agentPaceSamples = Array.isArray(data.agentPaceSamples) ? data.agentPaceSamples : [];
    if (data.startedAt) this.startedAt = data.startedAt;
    this.ready = !!data.ready;
    this.readyAt = data.readyAt || null;
    this.frozenPaceP95 = typeof data.frozenPaceP95 === 'number' ? data.frozenPaceP95 : null;
    this.etaMinutes = typeof data.etaMinutes === 'number' ? data.etaMinutes : null;
    this.notifications = Array.isArray(data.notifications) ? data.notifications : [];
    this.lastEtaNotifiedAt = data.lastEtaNotifiedAt || 0;
  }

  status() {
    return {
      mode: this.ready ? 'ENFORCE' : 'OBSERVE',
      ready: this.ready,
      requestsSeen: this.requestsSeen,
      distinctAgents: this.agentsSeen.size,
      confidence: Number(this.confidence().toFixed(2)),
      etaMinutes: this.etaMinutes,
      agentPaceP95: Math.round(this.agentPaceP95()),
      startedAt: new Date(this.startedAt).toISOString(),
      readyAt: this.readyAt ? new Date(this.readyAt).toISOString() : null,
      notifications: this.notifications.slice(-10),
    };
  }
}

module.exports = { Baseline, READINESS_NOTIFICATION };
