// Agent reputation registry (blueprint Phase 3).
//
// Every agent identity the guard meets — operator name when one is
// presented, otherwise the behavioural fingerprint — accumulates a
// reputation record: purpose-mismatch history (with timestamps), fast-path
// demotions, blocks, and breaking-change re-check outcomes. Score starts
// neutral (50): a mismatch costs 10, a demotion 15, a block 50; clean
// verified behaviour earns a little back (capped at 70 — good history
// never buys a free pass). Low reputation adds risk in scoring.
// Records persist in the durable store, so a restart does not forgive.
//
// Operator-level swarm correlation (the v0.1 documented limitation):
// fingerprints sharing one operator are tracked together. Four or more
// distinct nodes from one operator running the same task shape is a
// coordinated swarm, and each node gets a risk boost for it.
'use strict';

const SWARM_MIN_NODES = 4;
const SWARM_BOOST = 15;

class ReputationRegistry {
  constructor(store) {
    this.store = store || null;
    // store.data.reputation is a plain object: identity -> record.
    this.records = (store && store.data && store.data.reputation) || {};
    this.operatorNodes = new Map(); // operator -> Map<fingerprint, taskShape>
  }

  _save() {
    if (this.store) {
      this.store.data.reputation = this.records;
      this.store.saveSoon();
    }
  }

  _recordFor(identity, operator, fingerprint) {
    if (!this.records[identity]) {
      this.records[identity] = {
        identity,
        operator: operator || null,
        fingerprint: fingerprint || null,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        requests: 0,
        purposeMismatches: [],
        demotions: 0,
        blocks: 0,
        rechecks: [],
        fastPathGrants: 0,
        score: 50,
      };
    }
    return this.records[identity];
  }

  /** Observe one request from an identity (keeps counts and last-seen fresh). */
  observe(identity, { operator, fingerprint, taskShape }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.requests += 1;
    rec.lastSeen = new Date().toISOString();
    if (operator && fingerprint) {
      if (!this.operatorNodes.has(operator)) this.operatorNodes.set(operator, new Map());
      this.operatorNodes.get(operator).set(fingerprint, taskShape || 'unknown');
    }
    this._save();
    return rec;
  }

  recordMismatch(identity, { operator, fingerprint, purpose, drift }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.purposeMismatches.push({ at: new Date().toISOString(), purpose: purpose || null, drift: drift || null });
    if (rec.purposeMismatches.length > 50) rec.purposeMismatches.length = 50;
    rec.score = Math.max(0, rec.score - 10);
    this._save();
    return rec;
  }

  recordDemotion(identity, { operator, fingerprint, reason }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.demotions += 1;
    rec.purposeMismatches.push({ at: new Date().toISOString(), purpose: null, drift: reason || 'fast-path demotion' });
    rec.score = Math.max(0, rec.score - 15);
    this._save();
    return rec;
  }

  recordBlock(identity, { operator, fingerprint }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.blocks += 1;
    rec.score = 0;
    this._save();
    return rec;
  }

  recordRecheck(identity, { operator, fingerprint, outcome }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.rechecks.push({ at: new Date().toISOString(), outcome });
    if (rec.rechecks.length > 50) rec.rechecks.length = 50;
    this._save();
    return rec;
  }

  recordFastPathGrant(identity, { operator, fingerprint }) {
    const rec = this._recordFor(identity, operator, fingerprint);
    rec.fastPathGrants += 1;
    rec.score = Math.min(70, rec.score + 2);
    this._save();
    return rec;
  }

  /** Reputation risk penalty for scoring: 0 / +10 / +15. */
  penaltyFor(identity) {
    const rec = this.records[identity];
    if (!rec) return 0;
    if (rec.score < 10) return 15;
    if (rec.score < 30) return 10;
    return 0;
  }

  get(identity) {
    return this.records[identity] || null;
  }

  /** Coordinated-swarm signal: ≥4 nodes, one operator, one task shape. */
  swarmSignal(operator) {
    if (!operator) return null;
    const nodes = this.operatorNodes.get(operator);
    if (!nodes || nodes.size < SWARM_MIN_NODES) return null;
    const shapes = {};
    for (const shape of nodes.values()) shapes[shape] = (shapes[shape] || 0) + 1;
    const top = Object.entries(shapes).sort((a, b) => b[1] - a[1])[0];
    if (!top || top[1] < SWARM_MIN_NODES) return null;
    return {
      operator,
      nodes: nodes.size,
      taskShape: top[0],
      nodesOnShape: top[1],
      boost: SWARM_BOOST,
      reason: `coordinated swarm: ${top[1]} nodes from operator "${operator}" running the same "${top[0]}" task`,
    };
  }

  /** Top reputations for the dashboard (worst first). */
  topWorst(limit) {
    return Object.values(this.records)
      .sort((a, b) => a.score - b.score)
      .slice(0, limit || 10);
  }

  status() {
    return {
      identities: Object.keys(this.records).length,
      worst: this.topWorst(5).map((r) => ({
        identity: r.identity, score: r.score, requests: r.requests,
        mismatches: r.purposeMismatches.length, demotions: r.demotions, blocks: r.blocks,
      })),
    };
  }
}

module.exports = { ReputationRegistry, SWARM_MIN_NODES, SWARM_BOOST };
