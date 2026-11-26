// The Guard — the guardian agent itself (blueprint Sections 02-04, 06-07).
//
// Flow per request: INTERCEPT -> IDENTIFY -> OBSERVE & SCORE -> DECIDE -> ACT.
//   * Site starts in OBSERVE mode after install; enforcement switches on
//     only when the guard itself judges the baseline solid (guard-decided
//     readiness, live ETA). Nothing is blocked during observe — except the
//     narrow unambiguous-hostility exception (direct sensitive-path hits).
//   * First-time agents are watched and scored; the verified fast path is
//     the only shortcut (Web Bot Auth identity + authentic purpose +
//     behaviour match, re-checked every request, demotion to L1 on drift).
//   * Scoring weighs data sensitivity first (0-40), purpose mismatch
//     (0-25), velocity (0-20), evasion (0-15) — plus live signals from
//     injection detection, tool-chain rules, community rules, reputation,
//     swarm correlation, exfiltration shapes, and policy violations.
//   * Transactions require delegated authority (AP2 mandate or Visa TAP
//     token) once the guard is enforcing.
//   * A block is FINAL and permanent. There is no unblock method anywhere
//     in this class — deliberately. The dashboard is read-only visibility.
//   * Every decision is logged with its evidence to the incident feed and
//     the audit log. State (blocks, reputation, baseline, incidents)
//     survives restarts via the durable store.
'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');
const scoring = require('./scoring');
const { Session } = require('./taskGraph');
const firstContact = require('./firstContact');
const { Baseline } = require('./baseline');
const { buildDossier } = require('./dossier');
const webBotAuth = require('./webBotAuth');
const delegation = require('./delegation');
const injection = require('./injection');
const { IntegrityWatch } = require('./integrity');
const { ReputationRegistry } = require('./reputation');
const { loadPolicies, policyFor, checkPolicy } = require('./policies');
const { RuleMarketplace } = require('./rules');
const { DecoySession } = require('./decoy');
const { AuditLog, log } = require('./audit');
const { Store } = require('./store');

const BLOCKS_PATH = path.join(__dirname, 'data', 'blocks.json');

function fingerprintOf(req) {
  // Behavioural fingerprint: what the agent presents + where it comes from.
  // Unsigned agents are fingerprinted from observable signals alone.
  const ua = req.headers['user-agent'] || 'unknown';
  const op = req.headers['x-agent-operator'] || req.headers['signature-agent'] || '';
  const ip = req.socket.remoteAddress || 'local';
  return `${op}|${ua}|${ip}`.slice(0, 200);
}

function parseAgentHeaders(req) {
  return {
    operator: req.headers['x-agent-operator'] || req.headers['signature-agent'] || null,
    domain: req.headers['x-agent-domain'] || null,
    purpose: req.headers['x-agent-purpose'] || null,
    country: req.headers['x-agent-country'] || null,
    method: req.method || 'GET',
    url: req.url || '/',
    headers: req.headers || {},
    mandateHeader: req.headers['x-agent-mandate'] || null,
    tapHeader: req.headers['x-agent-tap'] || null,
    cardHeader: req.headers['x-agent-card'] || null,
    card: null, // decoded in handle() when a card header is present
    isHuman: /mozilla/i.test(req.headers['user-agent'] || '') && !/bot|agent|crawler|spider/i.test(req.headers['user-agent'] || ''),
  };
}

class Guard {
  constructor(options) {
    const opts = options || {};
    this.library = opts.library;
    this.agentPulse = opts.agentPulse || null;
    this.registry = opts.registry || webBotAuth.loadRegistry();
    this.store = opts.store || null;
    this.blocksPath = opts.blocksPath || BLOCKS_PATH;
    this.audit = opts.audit || new AuditLog();
    this.reputation = opts.reputation || new ReputationRegistry(this.store);
    this.policies = opts.policies || loadPolicies();
    this.rules = opts.rules || new RuleMarketplace();
    this.integrity = opts.integrity || new IntegrityWatch();
    this.intel = opts.intel || null;
    this.baseline = new Baseline();
    if (this.store && this.store.data.baseline) this.baseline.restore(this.store.data.baseline);
    this.profiles = new Map(); // fingerprint -> profile
    this.sessions = new Map(); // fingerprint -> Session
    this.blocked = new Map(); // fingerprint -> dossier (PERMANENT)
    this.decoys = new Map(); // fingerprint -> DecoySession (L4)
    this.incidents = (this.store && Array.isArray(this.store.data.incidents))
      ? this.store.data.incidents : [];
    this.observeFindings = []; // suspicious patterns noticed during observe
    this._loadBlocks();
  }

  _loadBlocks() {
    if (this.store) {
      for (const [fp, dossier] of Object.entries(this.store.data.blocks || {})) this.blocked.set(fp, dossier);
      return;
    }
    try {
      const saved = JSON.parse(fs.readFileSync(this.blocksPath, 'utf8'));
      for (const [fp, dossier] of Object.entries(saved)) this.blocked.set(fp, dossier);
    } catch (_) { /* no prior blocks */ }
  }

  _saveBlocks() {
    if (this.store) {
      this.store.data.blocks = Object.fromEntries(this.blocked);
      this.store.flush();
      return;
    }
    try {
      fs.writeFileSync(this.blocksPath, JSON.stringify(Object.fromEntries(this.blocked), null, 2));
    } catch (_) { /* blocks stay in memory if disk write fails */ }
  }

  /** Persist baseline + incidents (debounced) after a request. */
  _persistSoon() {
    if (!this.store) return;
    this.store.data.baseline = this.baseline.serialize();
    this.store.data.incidents = this.incidents.slice(0, 200);
    this.store.saveSoon();
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
    this._persistSoon();
  }

  /** The interactive L4 decoy session for a fingerprint (created on demand). */
  decoyFor(fingerprint) {
    if (!this.decoys.has(fingerprint)) this.decoys.set(fingerprint, new DecoySession(fingerprint));
    return this.decoys.get(fingerprint);
  }

  /**
   * The single entry point: inspect one request and return a decision.
   * decision = { action, rung, risk, confidence, reason, dossierId?, fingerprint }
   * Actions: allow | observe | challenge | throttle | sandbox | block | refuse
   */
  async handle(req) {
    const agent = parseAgentHeaders(req);
    const fingerprint = fingerprintOf(req);

    // Already blocked, forever. No override, no expiry, no second look.
    if (this.blocked.has(fingerprint)) {
      const dossier = this.blocked.get(fingerprint);
      return { action: 'block', rung: 'L5', risk: dossier.risk, confidence: 'HIGH', reason: 'permanently blocked — block is final', dossierId: dossier.id, fingerprint };
    }

    // Humans pass through untouched.
    if (agent.isHuman && !agent.operator) {
      this.baseline.observe('human', req.path, 0);
      this._persistSoon();
      return { action: 'allow', rung: 'L0', risk: 0, confidence: 'HIGH', reason: 'human browser traffic', fingerprint };
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

    // Reputation: observe every request (keeps counts, mismatch history).
    const identity = agent.operator || fingerprint;
    this.reputation.observe(identity, { operator: agent.operator, fingerprint, taskShape: session.taskShape() });

    // Delegated authority presented with this request (mandate / TAP / card).
    let mandate = null;
    let mandateError = null;
    if (agent.mandateHeader) {
      const decoded = delegation.decodeB64Json(agent.mandateHeader);
      if (!decoded.ok) mandateError = decoded.reason;
      else {
        const verified = delegation.verifyMandate(decoded.value, this.registry);
        if (verified.ok) mandate = verified;
        else mandateError = verified.reason;
      }
    }
    let tap = null;
    if (agent.tapHeader) {
      const decoded = delegation.decodeB64Json(agent.tapHeader);
      if (decoded.ok) {
        const verified = delegation.verifyTapToken(decoded.value, this.registry);
        if (verified.ok) tap = verified;
      }
    }
    if (agent.cardHeader) {
      const decoded = delegation.decodeB64Json(agent.cardHeader);
      if (decoded.ok) agent.card = decoded.value;
    }
    const delegatedAuthority = mandate || tap || null;
    // Expose verified delegation to the caller (the MCP door needs it for
    // order-status calls). Nothing here grants authority by itself.
    req.verifiedMandate = mandate;
    req.verifiedTap = tap;

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

    // Identity verification (Web Bot Auth, or a signed A2A agent card) —
    // done once per request and reused by the fast path and the policies.
    const identityCheck = await firstContact.verifyIdentity(agent, this.registry);
    agent.identityVerified = identityCheck.ok;

    // Fast-path handling: evaluate, or re-check if already on it.
    const fp = await firstContact.evaluateFastPath(agent, session, this.registry, identityCheck);
    if (profile.fastPathGranted) {
      const recheck = await firstContact.recheckFastPath(agent, session, this.registry);
      if (!recheck.stillValid) {
        profile.fastPathGranted = false;
        profile.purposeMismatch = true;
        this.reputation.recordDemotion(identity, { operator: agent.operator, fingerprint, reason: recheck.reason });
        this._logIncident('DEMOTED', `Agent "${agent.operator}" demoted from fast path`, recheck.reason);
        this.audit.record('fast_path_demoted', { operator: agent.operator, fingerprint: fingerprint.slice(0, 40), reason: recheck.reason });
        this._persistSoon();
        return { action: 'observe', rung: 'L1', risk: 40, confidence: 'MEDIUM', reason: `fast path revoked mid-session: ${recheck.reason}`, fingerprint };
      }
      return { action: 'allow', rung: 'VF', risk: 5, confidence: 'HIGH', reason: 'verified fast path — identity + purpose + behaviour match', fingerprint };
    }
    if (fp.granted) {
      profile.fastPathGranted = true;
      profile.known = true;
      this.reputation.recordFastPathGrant(identity, { operator: agent.operator, fingerprint });
      this._logIncident('FAST_PATH', `Agent "${agent.operator}" granted verified fast path`, fp.reason);
      this.audit.record('fast_path_granted', { operator: agent.operator, fingerprint: fingerprint.slice(0, 40), method: fp.checks.identity.method });
      this._persistSoon();
      return { action: 'allow', rung: 'VF', risk: 5, confidence: 'HIGH', reason: fp.reason, fingerprint };
    }

    // Score the task (not the single request).
    const score = scoring.scoreSession(profile, session, this.baseline.agentPaceP95());
    const requestText = `${req.url || ''} ${req.bodyText || ''}`;
    const libraryHits = this.library.match(session, profile, requestText);
    let boosted = Math.min(100, score.total + libraryHits.length * 5);
    const extraReasons = [...score.reasons];

    // Live detection signals (Phase 2/3) — each adds risk + a reason.
    const urlObj = new URL(req.url || '/', 'http://localhost');
    const injectionHits = injection.scanRequest({ query: urlObj.search || '', bodyText: req.bodyText || '', referer: req.headers['referer'] || '' });
    const echoHits = injection.scanEcho(requestText, this.integrity.poisonedSnippets);
    const libraryContentHits = injection.matchLibraryContentPatterns(requestText, this.library.entries);
    if (injectionHits.length) {
      boosted = Math.min(100, boosted + Math.min(20, injectionHits.length * 10));
      extraReasons.push(`prompt-injection patterns in request (${injectionHits.map((h) => h.pattern).join(', ')})`);
      this._logIncident('INJECTION', `Prompt-injection patterns from ${agent.operator || fingerprint.slice(0, 24)}`, injectionHits.map((h) => `${h.where}: ${h.pattern}`).join('; '));
    }
    if (echoHits.length) {
      boosted = Math.min(100, boosted + 15);
      extraReasons.push('request echoes site content carrying injected instructions (indirect injection)');
    }
    if (libraryContentHits.length) {
      boosted = Math.min(100, boosted + 10);
      extraReasons.push(`request text matches Threat Library content pattern (${libraryContentHits[0].entryId})`);
    }
    const toolChainHits = injection.matchToolChains(session.requests.map((r) => r.path));
    for (const tc of toolChainHits) {
      boosted = Math.min(100, boosted + Math.min(25, tc.risk));
      extraReasons.push(`tool-chain detected: ${tc.name}`);
    }
    const exfilSignals = IntegrityWatch.exfiltrationSignals(requestText);
    if (exfilSignals.length) {
      boosted = Math.min(100, boosted + Math.min(15, exfilSignals.length * 10));
      extraReasons.push(`disguised exfiltration shape (${exfilSignals.map((s) => s.kind).join(', ')})`);
    }
    const ruleHits = this.rules.match(session, { query: urlObj.search || '', userAgent: ua });
    for (const h of ruleHits) {
      if (h.rule.action === 'boost') boosted = Math.min(100, boosted + h.rule.risk);
      extraReasons.push(`community rule "${h.rule.id}": ${h.why}`);
    }
    const reputationPenalty = this.reputation.penaltyFor(identity);
    if (reputationPenalty > 0) {
      boosted = Math.min(100, boosted + reputationPenalty);
      extraReasons.push(`agent reputation ${this.reputation.get(identity).score}/100 adds +${reputationPenalty} risk`);
    }
    const swarm = this.reputation.swarmSignal(agent.operator);
    if (swarm) {
      boosted = Math.min(100, boosted + swarm.boost);
      extraReasons.push(swarm.reason);
    }

    // Per-endpoint / per-transaction policy check.
    const policy = policyFor(this.policies, req.method, req.path);
    const policyCheck = checkPolicy(policy, {
      agent: { purpose: agent.purpose, identityVerified: identityCheck.ok },
      mandate: delegatedAuthority, risk: boosted,
    });
    if (mandate && !delegation.mandateCovers(mandate.mandate, { endpoint: req.path, action: req.method })) {
      policyCheck.violations.push('mandate scope does not cover this endpoint');
      policyCheck.allowed = false;
    }
    if (policyCheck.violations.length) {
      extraReasons.push(...policyCheck.violations);
      boosted = Math.min(100, boosted + 10);
    }

    // Site-level observe mode: watch and score, never punish — but record
    // suspicious findings so they carry into enforcement at switch-on.
    // A finding is only recorded once the guard has enough of the task to
    // judge it (confidence above LOW, or at least 10 requests seen).
    if (!this.baseline.ready) {
      if (boosted >= 60 && (score.confidence !== 'LOW' || session.requests.length >= 10)) {
        this._recordObserveFinding(profile, session, boosted, libraryHits);
      }
      const becameReady = this.baseline.checkReady();
      if (becameReady) {
        this.audit.record('guard_ready', { requestsSeen: this.baseline.requestsSeen, confidence: this.baseline.confidence() });
        log('info', 'guard_ready', { requestsSeen: this.baseline.requestsSeen, confidence: this.baseline.confidence() });
        if (this.store) this.store.flush();
      }
      this._persistSoon();
      return { action: 'observe', rung: 'L1', risk: boosted, confidence: score.confidence, reason: `observing — provisional risk ${boosted} (${extraReasons.join('; ') || 'pattern still building'})`, fingerprint };
    }

    // Enforcing: a transaction without delegated authority is denied.
    if (policy && policy.requireMandate && !delegatedAuthority) {
      const reason = mandateError
        ? `transaction requires a delegated-authority mandate — presented mandate invalid: ${mandateError}`
        : 'transaction requires a delegated-authority mandate (AP2 mandate or Visa TAP token)';
      this._logIncident('POLICY_DENY', `Transaction denied for ${agent.operator || fingerprint.slice(0, 24)}`, reason);
      this.audit.record('policy_denied', { operator: agent.operator, fingerprint: fingerprint.slice(0, 40), path: req.path, reason });
      this._persistSoon();
      return { action: 'challenge', rung: 'L2', risk: boosted, confidence: score.confidence, reason, fingerprint };
    }

    // Enforce: map the score to the ladder.
    const rung = scoring.ladderFor(boosted);
    if (rung.action === 'allow') {
      profile.known = true;
      this._persistSoon();
      return { action: 'allow', rung: rung.rung, risk: boosted, confidence: score.confidence, reason: 'known benign pattern', fingerprint };
    }
    if (rung.action === 'block') {
      return this._block(profile, session, agent, extraReasons.join('; ') || 'risk threshold reached', boosted, score, libraryHits);
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
      this._logIncident(rung.action.toUpperCase(), `Agent ${agent.operator || fingerprint.slice(0, 24)} → ${rung.rung} ${rung.action}`, `risk ${boosted}: ${extraReasons.join('; ')}`);
    }
    this._persistSoon();
    return { action: rung.action, rung: rung.rung, risk: boosted, confidence: score.confidence, reason: extraReasons.join('; ') || `risk ${boosted}`, fingerprint };
  }

  /** Record a data-integrity finding (poisoning / content change) as an incident. */
  recordIntegrityFinding(finding) {
    const entry = { at: new Date().toISOString(), ...finding };
    this._logIncident('INTEGRITY', `Data-integrity watch: ${finding.detail || finding.kind}`, finding.detail || '', { finding: entry });
    this.audit.record('integrity_finding', { kind: finding.kind, id: finding.id || null, detail: finding.detail || null });
    this._persistSoon();
    return entry;
  }

  /**
   * Decision API for edge workers and gateway plugins: decide on a request
   * descriptor without serving content. The decision is real — the request
   * is observed and scored exactly as if it had arrived at the guard.
   */
  async decideDescriptor({ method, path, query, headers }) {
    const req = {
      method: method || 'GET',
      url: `${path || '/'}${query || ''}`,
      path: path || '/',
      headers: headers || {},
      socket: { remoteAddress: 'edge' },
      bodyText: '',
    };
    return this.handle(req);
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
    const identity = agent.operator || profile.fingerprint;
    this.reputation.recordBlock(identity, { operator: agent.operator, fingerprint: profile.fingerprint });
    this._logIncident('BLOCKED', `Agent ${agent.operator || profile.fingerprint.slice(0, 24)} blocked (risk ${finalRisk})`, reason, { dossierId: dossier.id });
    this.audit.record('blocked', { operator: agent.operator, fingerprint: profile.fingerprint.slice(0, 40), risk: finalRisk, reason, dossierId: dossier.id });
    if (this.store) this.store.flush();
    return { action: 'block', rung: 'L5', risk: finalRisk, confidence: 'HIGH', reason, dossierId: dossier.id, fingerprint: profile.fingerprint };
  }

  /**
   * AgentPulse breaking-change re-check trigger: when a dependency API
   * changes, immediately re-score and re-verify every agent touching it.
   * Demotes mismatches to L1 on the spot; outcomes are recorded in the
   * reputation registry. (Demo trigger: simulate.js --breaking-change,
   * or POST /guard/demo/breaking-change.)
   */
  async recheckAgentsForDependency(dependency) {
    const results = [];
    for (const [fp, profile] of this.profiles.entries()) {
      if (this.blocked.has(fp)) continue; // already final — nothing to re-check
      const session = this.sessions.get(fp);
      if (!session) continue;
      const touches = session.requests.some((r) => r.path.includes(dependency));
      if (!touches) continue;
      const agent = {
        operator: profile.operator, purpose: profile.purpose,
        method: 'GET', url: '/', headers: {},
      };
      const score = scoring.scoreSession(profile, session, this.baseline.agentPaceP95());
      const fpCheck = profile.fastPathGranted
        ? await firstContact.recheckFastPath(agent, session, this.registry)
        : null;
      const identity = profile.operator || fp;
      if (fpCheck && !fpCheck.stillValid) {
        profile.fastPathGranted = false;
        profile.purposeMismatch = true;
        this.reputation.recordRecheck(identity, { operator: profile.operator, fingerprint: fp, outcome: 'demoted to L1 — purpose/behaviour mismatch after API change' });
        results.push({ fingerprint: fp.slice(0, 24), outcome: 'demoted to L1 — purpose/behaviour mismatch after API change' });
        this._logIncident('RE-CHECK', `Agent ${profile.operator} demoted after breaking change in ${dependency}`, fpCheck.reason);
      } else {
        this.reputation.recordRecheck(identity, { operator: profile.operator, fingerprint: fp, outcome: `re-scored risk ${score.total} — still matches stated purpose` });
        results.push({ fingerprint: fp.slice(0, 24), outcome: `re-scored risk ${score.total} — still matches stated purpose` });
      }
    }
    this._logIncident('RE-CHECK', `Breaking-change re-check for dependency "${dependency}"`, `${results.length} agent(s) re-checked`);
    this.audit.record('breaking_change_recheck', { dependency, rechecked: results.length });
    this._persistSoon();
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

  /** Compliance report: counts, blocks, policy coverage, feed health. */
  complianceReport() {
    const auditEntries = this.audit.readAll(1000);
    const byEvent = {};
    for (const e of auditEntries) byEvent[e.event] = (byEvent[e.event] || 0) + 1;
    const feed = this.agentPulse ? this.agentPulse.breakingChangeSignal() : null;
    return {
      generatedAt: new Date().toISOString(),
      site: config.siteName,
      mode: this.baseline.ready ? 'ENFORCE' : 'OBSERVE',
      totals: {
        requestsSeen: this.baseline.requestsSeen,
        agentsTracked: this.profiles.size,
        blockedForever: this.blocked.size,
        fastPathActive: [...this.profiles.values()].filter((p) => p.fastPathGranted).length,
      },
      blocks: [...this.blocked.values()].map((d) => ({
        id: d.id, operator: d.companyOperator, risk: d.risk, blockedAt: d.blockedAt, whyBlocked: d.whyBlocked,
      })),
      decisions: byEvent,
      policies: { version: this.policies.version, endpoints: this.policies.endpoints.length },
      rules: { enabled: this.rules.rules.length, invalid: this.rules.invalid.length },
      library: this.library.summary(),
      reputation: this.reputation.status(),
      integrity: this.integrity.status(),
      intel: this.intel ? this.intel.status() : { pending: 0, mergedTotal: 0, lastMerge: null },
      agentPulse: feed ? { ...feed, lastError: this.agentPulse.lastError } : null,
      retention: 'Audit log retained locally and rotated past 5 MB. Blocks are permanent and never expire.',
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
      reputation: this.reputation.status(),
      policies: { version: this.policies.version, endpoints: this.policies.endpoints.length },
      rules: { enabled: this.rules.rules.length, invalid: this.rules.invalid.length },
      integrity: this.integrity.status(),
      intel: this.intel ? this.intel.status() : { pending: 0, mergedTotal: 0, lastMerge: null },
      agentPulse: this.agentPulse ? {
        lastPolledAt: this.agentPulse.lastPolledAt,
        lastError: this.agentPulse.lastError,
        signal: this.agentPulse.breakingChangeSignal(),
      } : null,
    };
  }
}

// NOTE: there is deliberately no unblock(), allowlist(), or override()
// method on this class. A block is final and permanent.
module.exports = { Guard, fingerprintOf, parseAgentHeaders };
