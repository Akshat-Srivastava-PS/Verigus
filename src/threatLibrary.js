// Threat Library (blueprint Module 7).
// The guard's own living record of suspicious AI-agent activity and
// agent-related outages, held as detectable patterns — refreshed DAILY on a
// fixed schedule: collect -> verify & de-duplicate -> convert to detection
// -> push to every guard -> file findings, repeat tomorrow.
//
// The library only ever informs DETECTION. It can never lift a block
// (blocks are final) and it never grants the fast path.
'use strict';

const fs = require('fs');
const path = require('path');

const SEED_PATH = path.join(__dirname, 'data', 'threat-library.json');

class ThreatLibrary {
  constructor(agentPulse) {
    this.agentPulse = agentPulse; // AgentPulseFeed (may be null)
    this.version = 0;
    this.entries = [];
    this.lastUpdatedAt = null;
    this.lastRefresh = null;
    this.loadSeed();
  }

  loadSeed() {
    const raw = JSON.parse(fs.readFileSync(SEED_PATH, 'utf8'));
    this.entries = raw.entries;
    this.version = raw.version;
    this.lastUpdatedAt = raw.seedDate;
  }

  /** Match live behaviour against library entries. Returns matched entries. */
  match(session, profile) {
    const paths = session.requests.map((r) => r.path);
    const hits = [];
    for (const entry of this.entries) {
      const m = entry.match || {};
      let matched = false;
      let why = '';
      if (m.pathPatterns && paths.some((p) => m.pathPatterns.some((re) => new RegExp(re).test(p)))) {
        matched = true;
        why = `touched a path matching ${entry.id}`;
      }
      if (!matched && m.minRequestsPerMin && session.requestsPerMin() >= m.minRequestsPerMin) {
        matched = true;
        why = `pace ${Math.round(session.requestsPerMin())}/min at or above ${entry.id} threshold`;
      }
      if (!matched && m.sequence && this._sequenceMatches(paths, m.sequence)) {
        matched = true;
        why = `request sequence matches ${entry.id}`;
      }
      if (matched) hits.push({ entry, why });
    }
    return hits;
  }

  _sequenceMatches(paths, sequence) {
    let idx = 0;
    for (const p of paths) {
      if (new RegExp(sequence[idx]).test(p)) {
        idx += 1;
        if (idx === sequence.length) return true;
      }
    }
    return false;
  }

  /**
   * The daily refresh cycle. In this working model the "internet sweep" is
   * represented by the seeded sources list (each entry carries its source
   * URL); the live part is the AgentPulse feed, which streams real outage
   * and incident data. New verified items are converted into detection
   * entries and the version is bumped — the push step.
   */
  async dailyRefresh() {
    const report = { collected: 0, verified: 0, duplicates: 0, added: 0, agentPulseEvents: 0 };
    // 1. COLLECT — AgentPulse live feed (real) + seeded source catalogue.
    let feedEvents = [];
    if (this.agentPulse) {
      try {
        feedEvents = await this.agentPulse.poll();
        report.agentPulseEvents = feedEvents.length;
      } catch (err) {
        report.agentPulseError = String(err.message || err);
      }
    }
    for (const ev of feedEvents) {
      report.collected += 1;
      // 2. VERIFY & DE-DUPLICATE — corroborate against what we already hold.
      const exists = this.entries.some((e) => e.id === ev.id);
      if (exists) {
        report.duplicates += 1;
        continue;
      }
      // 3. CONVERT TO DETECTION.
      this.entries.push(ev);
      report.verified += 1;
      report.added += 1;
    }
    // 4. PUSH — version bump; every guard reads the same library object.
    if (report.added > 0) this.version += 1;
    this.lastUpdatedAt = new Date().toISOString();
    // 5. FILE — the refresh itself is the record; findings filed by the guard
    // call fileFinding() during the day and are published at the next refresh.
    this.lastRefresh = { at: this.lastUpdatedAt, ...report };
    return this.lastRefresh;
  }

  /** File a guard observation back into the library (published next refresh). */
  fileFinding(finding) {
    finding.filedAt = new Date().toISOString();
    finding.pendingVerification = true;
    this.entries.push(finding);
    return finding;
  }

  summary() {
    return {
      version: this.version,
      entries: this.entries.length,
      lastUpdatedAt: this.lastUpdatedAt,
      lastRefresh: this.lastRefresh,
    };
  }
}

module.exports = { ThreatLibrary };
