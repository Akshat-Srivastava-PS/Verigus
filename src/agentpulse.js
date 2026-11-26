// AgentPulse integration — the guard's integrated outage-intelligence feed.
//
// AgentPulse is part of this product, not a separate tool. Its live feed
// streams real API/cloud status, outages, incidents and breaking changes
// into the Threat Library. This client polls the live AgentPulse service
// (verified live 2026-11-26: GET /v1/metrics returns real JSON — 37
// services, active incidents, breaking-change counts). If the feed is
// unreachable the guard keeps working on its seeded library and logs the
// outage; the feed never blocks a decision.
//
// Breaking-change signal: when AgentPulse's breaking-change count rises,
// the guard immediately re-checks every agent touching the affected
// dependency (see guard.js recheckAgentsForDependency) — it does not wait
// for the next daily library update.
'use strict';

const config = require('./config');

function fetchJson(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https://') ? require('https') : require('http');
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(body)); } catch (e) { reject(new Error(`AgentPulse returned non-JSON from ${url}`)); }
        } else {
          reject(new Error(`AgentPulse HTTP ${res.statusCode} from ${url}`));
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('AgentPulse request timed out')); });
    req.on('error', reject);
  });
}

class AgentPulseFeed {
  constructor(baseUrl) {
    this.baseUrl = (baseUrl || config.agentPulseBaseUrl).replace(/\/$/, '');
    this.lastSnapshot = null;
    this.lastError = null;
    this.lastPolledAt = null;
  }

  /**
   * Poll the live feed. Returns library-ready events (empty array when
   * nothing new). Each event is a Threat Library entry.
   */
  async poll() {
    const url = `${this.baseUrl}${config.agentPulseFeedPath}`;
    const snap = await fetchJson(url);
    this.lastPolledAt = new Date().toISOString();
    this.lastError = null;

    const events = [];
    const prev = this.lastSnapshot;
    this.lastSnapshot = snap;

    const services = snap.services || {};
    const degraded = services.degraded || 0;
    const outage = services.outage || 0;
    const incidents = snap.active_incidents || 0;
    const breaking = snap.total_breaking_changes || 0;

    // Outage / degradation signals become library entries.
    if (outage > 0 || degraded > 0) {
      events.push({
        id: `agentpulse-outage-${new Date().toISOString().slice(0, 10)}`,
        name: 'AgentPulse: live service degradation / outage signal',
        category: 'outage',
        severity: outage > 0 ? 'high' : 'medium',
        description: `AgentPulse reports ${outage} service(s) in outage and ${degraded} degraded across ${services.total || '?'} tracked services, with ${incidents} active incident(s). The guard watches for traffic shapes that match outage-driven agent behaviour (retry storms, fallback scraping).`,
        source: `${this.baseUrl}${config.agentPulseFeedPath}`,
        match: { minRequestsPerMin: 120 },
      });
    }

    // Breaking-change signal: a rising count is the re-check trigger.
    if (prev && typeof prev.total_breaking_changes === 'number' && breaking > prev.total_breaking_changes) {
      events.push({
        id: `agentpulse-breaking-change-${Date.now()}`,
        name: 'AgentPulse: breaking change detected in a dependency API',
        category: 'breaking-change',
        severity: 'high',
        description: `AgentPulse breaking-change count rose from ${prev.total_breaking_changes} to ${breaking}. The guard must immediately re-score and re-verify every agent touching the changed dependency.`,
        source: `${this.baseUrl}${config.agentPulseFeedPath}`,
        breakingChange: true,
        match: {},
      });
    }
    return events;
  }

  /** Did the latest snapshot contain a breaking-change signal? */
  breakingChangeSignal() {
    if (!this.lastSnapshot) return null;
    return {
      totalBreakingChanges: this.lastSnapshot.total_breaking_changes || 0,
      activeIncidents: this.lastSnapshot.active_incidents || 0,
      services: this.lastSnapshot.services || {},
      polledAt: this.lastPolledAt,
    };
  }
}

module.exports = { AgentPulseFeed, fetchJson };
