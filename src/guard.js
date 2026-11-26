// The Guard — the guardian agent itself (blueprint Sections 02-04, 06-07).
//
// Flow per request: INTERCEPT -> IDENTIFY -> OBSERVE & SCORE -> DECIDE -> ACT.
//   * Site starts in OBSERVE mode after install; enforcement switches on
//     only when the guard itself judges the baseline solid (guard-decided
//     readiness, live ETA). Nothing is blocked during observe — except the
//     narrow unambiguous-hostility exception (direct sensitive-path hits).
//   * First-time agents are watched and scored; the verified fast path is
//     the only shortcut (identity + authentic purpose + behaviour match,
//     re-checked every request, demotion to L1 on drift).
//   * A block is FINAL and permanent. There is no unblock method anywhere
//     in this class — deliberately. The dashboard is read-only visibility.
//   * Every decision is logged with its evidence to the incident feed.
'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');
const scoring = require('./scoring');
const { Session } = require('./taskGraph');
const firstContact = require('./firstContact');
const { Baseline } = require('./baseline');
const { buildDossier } = require('./dossier');

const BLOCKS_PATH = path.join(__dirname, 'data', 'blocks.json');

function fingerprintOf(req) {
  // Behavioural fingerprint: what the agent presents + where it comes from.
  // Unsigned agents are fingerprinted from observable signals alone.
  const ua = req.headers['user-agent'] || 'unknown';
  const op = req.headers['x-agent-operator'] || '';
  const ip = req.socket.remoteAddress || 'local';
  return `${op}|${ua}|${ip}`.slice(0, 200);
}

function parseAgentHeaders(req) {
  return {
    operator: req.headers['x-agent-operator'] || null,
    domain: req.headers['x-agent-domain'] || null,
    purpose: req.headers['x-agent-purpose'] || null,
    signature: req.headers['x-agent-signature'] || null,
    signedAt: req.headers['x-agent-signed-at'] || null,
    country: req.headers['x-agent-country'] || null,
    isHuman: /mozilla/i.test(req.headers['user-agent'] || '') && !/bot|agent|crawler|spider/i.test(req.headers['user-agent'] || ''),
  };
}

class Guard {
  constructor({ library, agentPulse, demoOperatorKey, blocksPath }) {
    this.library = library;
    this.agentPulse = agentPulse;
    this.demoOperatorKey = demoOperatorKey;
    // Where permanent blocks persist. Overridable so tests can use a
    // scratch file — otherwise a block saved by one run would make the
    // next run's agent already-blocked from its first request.
    this.blocksPath = blocksPath || BLOCKS_PATH;
    this.baseline = new Baseline();
    this.profiles = new Map(); // fingerprint -> profile
    this.sessions = new Map(); // fingerprint -> Session
    this.blocked = new Map(); // fingerprint -> dossier (PERMANENT)
    this.incidents = []; // newest first, capped
    this.observeFindings = []; // suspicious patterns noticed during observe
    this._loadBlocks();
  }

  _loadBlocks() {
    try {
      const saved = JSON.parse(fs.readFileSync(this.blocksPath, 'utf8'));
      for (const [fp, dossier] of Object.entries(saved)) this.blocked.set(fp, dossier);
    } catch (_) { /* no prior blocks */ }
  }

  _saveBlocks() {
    try {
      fs.writeFileSync(this.blocksPath, JSON.stringify(Object.fromEntries(this.blocked), null, 2));
    } catch (_) { /* blocks stay in memory if disk write fails */ }
  }

  _profileFor(fingerprint, agent) {
    if (!this.profiles.has(fingerprint)) {
      this.profiles.set(fingerprint, {
        fingerprint,
        operator: agent.operator,
        purpose: agent.purpose,
        country: agent.country,
        firstSeenAt: Date.now(),
        requests: 0,
        identityRotations: 0,
        uaSpoofSuspected: false,
        headlessSuspected: false,
        countryHops: 0,
        purposeMismatch: false,
        fastPathGranted: false,
        throttleCount: 0,
        lastLogKey: null, // dedup key for repeated decision incidents
        known: false,
        baselineP95: 0,
        lastCountry: agent.country,
      });
    }
    return this.profiles.get(fingerprint);
  }

  _sessionFor(fingerprint) {
    if (!this.sessions.has(fingerprint)) this.sessions.set(fingerprint, new Session(fingerprint));
    return this.sessions.get(fingerprint);
  }

  _logIncident(kind, summary, detail, extra) {
    this.incidents.unshift({ at: new Date().toISOString(), kind, summary, detail, ...(extra || {}) });
    if (this.incidents.length > 200) this.incidents.length = 200;
  }

  /**
   * The single entry point: inspect one request and return a decision.
   * decision = { action, rung, risk, confidence, reason, dossierId? }
   * Actions: allow | observe | challenge | throttle | sandbox | block | refuse
   */
  handle(req) {
    const agent = parseAgentHeaders(req);
    const fingerprint = fingerprintOf(req);

    // Already blocked, forever. No override, no expiry, no second look.
    if (this.blocked.has(fingerprint)) {
      const dossier = this.blocked.get(fingerprint);
      return { action: 'block', rung: 'L5', risk: dossier.risk, confidence: 'HIGH', reason: 'permanently blocked — block is final', dossierId: dossier.id };
    }

    // Humans pass through untouched.
    if (agent.isHuman && !agent.operator) {
      this.baseline.observe('human', req.path, 0);
      return { action: 'allow', rung: 'L0', risk: 0, confidence: 'HIGH', reason: 'human browser traffic' };
    }

    const profile = this._profileFor(fingerprint, agent);
    const session = this._sessionFor(fingerprint);
    profile.requests += 1;

    // Track evasion signals.
    if (agent.country && profile.lastCountry && agent.country !== profile.lastCountry) profile.countryHops += 1;
    if (agent.country) profile.lastCountry = agent.country;
    // Headless / automation fingerprints in the user agent.
    const ua = req.headers['user-agent'] || '';
    if (/headless|phantomjs|selenium|puppeteer|playwright/i.test(ua) || ua === '' || ua === 'unknown') {
      profile.headlessSuspected = true;
    }

    // Record the request first so the block dossier (if any) includes the
    // very path that triggered it.
    session.add({ path: req.path, method: req.method, dataClass: scoring.sensitivityOf(req.path).label });

    // Narrow exception: unambiguously hostile on its own — instant refuse,
    // even during observe mode.
    if (config.instantRefusePaths.some((re) => re.test(req.path))) {
      const score = scoring.scoreSession(profile, session, this.baseline.agentPaceP95());
      const libraryHits = this.library.match(session, profile);
      return this._block(profile, session, agent, 'direct hit on a known sensitive path — unambiguous hostility', 94, score, libraryHits);
    }

    // Baseline learning (observe mode feeds the site baseline).
    const rpm = session.requestsPerMin();
    this.baseline.observe(fingerprint, req.path, rpm);
    profile.baselineP95 = this.baseline.agentPaceP95();

    // Fast-path handling: evaluate, or re-check if already on it.
    const fp = firstContact.evaluateFastPath(agent, session, this.demoOperatorKey);
    if (profile.fastPathGranted) {
      const recheck = firstContact.recheckFastPath(agent, session, this.demoOperatorKey);
      if (!recheck.stillValid) {
        profile.fastPathGranted = false;
        profile.purposeMismatch = true;
        this._logIncident('DEMOTED', `Agent "${agent.operator}" demoted from fast path`, recheck.reason);
        return { action: 'observe', rung: 'L1', risk: 40, confidence: 'MEDIUM', reason: `fast path revoked mid-session: ${recheck.reason}` };
      }
      return { action: 'allow', rung: 'VF', risk: 5, confidence: 'HIGH', reason: 'verified fast path — identity + purpose + behaviour match' };
    }
    if (fp.granted) {
      profile.fastPathGranted = true;
      profile.known = true;
      this._logIncident('FAST_PATH', `Agent "${agent.operator}" granted verified fast path`, fp.reason);
      return { action: 'allow', rung: 'VF', risk: 5, confidence: 'HIGH', reason: fp.reason };
    }

    // Score the task (not the single request).
    const score = scoring.scoreSession(profile, session, this.baseline.agentPaceP95());
    const libraryHits = this.library.match(session, profile);
    const boosted = Math.min(100, score.total + libraryHits.length * 5);

    // Site-level observe mode: watch and score, never punish — but record
    // suspicious findings so they carry into enforcement at switch-on.
    // A finding is only recorded once the guard has enough of the task to
    // judge it (confidence above LOW, or at least 10 requests seen).
    if (!this.baseline.ready) {
      if (boosted >= 60 && (score.confidence !== 'LOW' || session.requests.length >= 10)) {
        this._recordObserveFinding(profile, session, boosted, libraryHits);
      }
      this.baseline.checkReady();
      return { action: 'observe', rung: 'L1', risk: boosted, confidence: score.confidence, reason: `observing — provisional risk ${boosted} (${score.reasons.join('; ') || 'pattern still building'})` };
    }

    // Enforce: map the score to the ladder.
    const rung = scoring.ladderFor(boosted);
    if (rung.action === 'allow') {
      profile.known = true;
      return { action: 'allow', rung: rung.rung, risk: boosted, confidence: score.confidence, reason: 'known benign pattern' };
    }
    if (rung.action === 'block') {
      return this._block(profile, session, agent, score.reasons.join('; ') || 'risk threshold reached', boosted, score, libraryHits);
    }
    // Escalation: three throttles and the agent is done — a repeat offender
    // that keeps coming back at throttle level is escalated to a final block.
    if (rung.action === 'throttle') {
      profile.throttleCount += 1;
      if (profile.throttleCount >= 3) {
        return this._block(profile, session, agent, `repeated throttling — ${profile.throttleCount} strikes, escalated to a permanent block`, boosted, score, libraryHits);
      }
    }
    // The incident feed logs DECISION TRANSITIONS, not every repeated
    // decision: a swarm firing 240 identical observes would otherwise
    // drown the feed (and push real BLOCKED entries out of it). A new
    // rung/action for this agent logs once; repeats stay silent.
    const logKey = `${rung.rung}:${rung.action}`;
    if (profile.lastLogKey !== logKey) {
      profile.lastLogKey = logKey;
      this._logIncident(rung.action.toUpperCase(), `Agent ${agent.operator || fingerprint.slice(0, 24)} → ${rung.rung} ${rung.action}`, `risk ${boosted}: ${score.reasons.join('; ')}`);
    }
    return { action: rung.action, rung: rung.rung, risk: boosted, confidence: score.confidence, reason: score.reasons.join('; ') || `risk ${boosted}` };
  }

  _recordObserveFinding(profile, session, risk, libraryHits) {
    const key = `${profile.fingerprint}:${session.taskShape()}`;
    if (this.observeFindings.some((f) => f.key === key)) return;
    this.observeFindings.push({
      key,
      fingerprint: profile.fingerprint,
      operator: profile.operator,
      taskShape: session.taskShape(),
      risk,
      paths: [...new Set(session.requests.map((r) => r.path))],
      libraryMatch: libraryHits[0] ? libraryHits[0].entry.id : null,
      at: new Date().toISOString(),
    });
  }

  _block(profile, session, agent, reason, risk, score, libraryHits) {
    const finalRisk = risk ?? 94;
    const finalScore = score || { total: finalRisk, confidence: 'HIGH', breakdown: { dataSensitivity: 38, purposeMismatch: 24, velocity: 17, evasion: 15 }, reasons: [reason] };
    const dossier = buildDossier({
      agent: { ...agent, identityVerified: false, fastPathGranted: profile.fastPathGranted },
      profile,
      session,
      score: finalScore,
      ladder: { rung: 'L5' },
      libraryHits: libraryHits || [],
    });
    dossier.whyBlocked = reason + '.';
    // The dossier records the risk that actually triggered the block
    // (score + Threat Library boost, or the instant-refuse floor for
    // unambiguous hostility). The component breakdown still sums to the
    // unboosted score; the library contribution is shown separately.
    dossier.risk = finalRisk;
    dossier.libraryBoost = (libraryHits || []).length * 5;
    this.blocked.set(profile.fingerprint, dossier);
    this._saveBlocks();
    this._logIncident('BLOCKED', `Agent ${agent.operator || profile.fingerprint.slice(0, 24)} blocked (risk ${finalRisk})`, reason, { dossierId: dossier.id });
    return { action: 'block', rung: 'L5', risk: finalRisk, confidence: 'HIGH', reason, dossierId: dossier.id };
  }

  /**
   * AgentPulse breaking-change re-check trigger: when a dependency API
   * changes, immediately re-score and re-verify every agent touching it.
   * Demotes mismatches to L1 on the spot. (Demo trigger: simulate.js
   * --breaking-change, or POST /guard/demo/breaking-change on localhost.)
   */
  recheckAgentsForDependency(dependency) {
    const results = [];
    for (const [fp, profile] of this.profiles.entries()) {
      if (this.blocked.has(fp)) continue; // already final — nothing to re-check
      const session = this.sessions.get(fp);
      if (!session) continue;
      const touches = session.requests.some((r) => r.path.includes(dependency));
      if (!touches) continue;
      const agent = { operator: profile.operator, purpose: profile.purpose, signature: null, signedAt: null };
      const score = scoring.scoreSession(profile, session, this.baseline.agentPaceP95());
      const fpCheck = profile.fastPathGranted
        ? firstContact.recheckFastPath(agent, session, this.demoOperatorKey)
        : null;
      if (fpCheck && !fpCheck.stillValid) {
        profile.fastPathGranted = false;
        profile.purposeMismatch = true;
        results.push({ fingerprint: fp.slice(0, 24), outcome: 'demoted to L1 — purpose/behaviour mismatch after API change' });
        this._logIncident('RE-CHECK', `Agent ${profile.operator} demoted after breaking change in ${dependency}`, fpCheck.reason);
      } else {
        results.push({ fingerprint: fp.slice(0, 24), outcome: `re-scored risk ${score.total} — still matches stated purpose` });
      }
    }
    this._logIncident('RE-CHECK', `Breaking-change re-check for dependency "${dependency}"`, `${results.length} agent(s) re-checked`);
    return results;
  }

  /** The learning report attached to the readiness notification. */
  learningReport() {
    const topEndpoints = [...this.baseline.endpointCounts.entries()]
      .sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([path, count]) => ({ path, count }));
    return {
      part1NormalPatterns: {
        requestsObserved: this.baseline.requestsSeen,
        distinctAgents: this.baseline.agentsSeen.size,
        agentPaceP95: Math.round(this.baseline.agentPaceP95()),
        topEndpoints,
        baselineConfidence: Number(this.baseline.confidence().toFixed(2)),
        whyReady: 'Normal patterns repeated consistently enough that abnormal behaviour can now be told apart from them.',
      },
      part2SuspiciousFindings: this.observeFindings.map((f) => ({
        ...f,
        reactionFromNow: 'Carried into enforcement with its observed score — the next visit starts from this profile, not a blank slate.',
      })),
    };
  }

  status() {
    return {
      site: config.siteName,
      mode: this.baseline.ready ? 'ENFORCE' : 'OBSERVE',
      baseline: this.baseline.status(),
      library: this.library.summary(),
      agentsTracked: this.profiles.size,
      blockedForever: this.blocked.size,
      fastPathActive: [...this.profiles.values()].filter((p) => p.fastPathGranted).length,
      incidents: this.incidents.slice(0, 20),
    };
  }
}

// NOTE: there is deliberately no unblock(), allowlist(), or override()
// method on this class. A block is final and permanent.
module.exports = { Guard, fingerprintOf, parseAgentHeaders };
