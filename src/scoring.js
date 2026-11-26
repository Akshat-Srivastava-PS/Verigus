// Scoring — data sensitivity weighted FIRST, call velocity SECOND.
// Mirrors the blueprint's dossier score breakdown:
//   Data sensitivity of targets:  0-40
//   Behaviour vs. stated purpose: 0-25
//   Velocity anomaly:             0-20
//   Evasion signals:              0-15
//   TOTAL RISK:                   0-100
'use strict';

const config = require('./config');

/** Sensitivity score (0-40) for a single path. */
function sensitivityOf(path) {
  for (const entry of config.sensitivity) {
    if (entry.pattern.test(path)) return { score: entry.score, label: entry.label };
  }
  return { score: 2, label: 'public content' };
}

/** Highest sensitivity seen across a session's requests. */
function sessionSensitivity(requests) {
  let best = { score: 0, label: 'none yet' };
  for (const r of requests) {
    const s = sensitivityOf(r.path);
    if (s.score > best.score) best = s;
  }
  return best;
}

/**
 * Velocity anomaly (0-20): how far the agent's pace sits above this site's
 * learned agent baseline. Pace is measured as requests in the trailing
 * 10-second window, extrapolated to requests/min; the baseline is the
 * p95 pace (requests/min) of benign agents observed during observe mode.
 */
function velocityScore(burstCount, baselinePace) {
  const burstRpm = burstCount * 6; // 10-second window -> requests/min
  if (!baselinePace || baselinePace <= 0) return burstRpm >= 120 ? 10 : 0;
  const ratio = burstRpm / baselinePace;
  if (ratio <= 1) return 0;
  if (ratio <= 2) return 5;
  if (ratio <= 5) return 10;
  if (ratio <= 10) return 15;
  return 20;
}

/**
 * Purpose-match score (0-25): 0 = behaviour stays inside the shape its
 * stated purpose predicts; 25 = wholly inconsistent with it.
 */
function purposeMismatchScore(profile, requests) {
  if (!profile.purpose) return 0; // unsigned agents are scored on behaviour, not purpose
  const shapes = config.purposeShapes[profile.purpose] || null;
  if (!shapes) return 15; // purpose not recognised for this site
  let outside = 0;
  for (const r of requests) {
    if (!shapes.some((re) => re.test(r.path))) outside += 1;
  }
  if (outside === 0) return 0;
  const ratio = outside / requests.length;
  if (ratio < 0.2) return 8;
  if (ratio < 0.5) return 16;
  return 25;
}

/**
 * Evasion signals (0-15): identity rotation, UA spoofing / headless
 * fingerprints, impossible travel / country hops.
 */
function evasionScore(profile) {
  let score = 0;
  if (profile.identityRotations >= 3) score += 8;
  else if (profile.identityRotations >= 1) score += 4;
  if (profile.uaSpoofSuspected) score += 4;
  if (profile.headlessSuspected) score += 5;
  if (profile.countryHops >= 2) score += 3;
  return Math.min(15, score);
}

/** Bulk-export volume bonus (0-15): the more catalog/API data pulled in one
 * task, the more the task looks like bulk capture rather than browsing. */
function volumeBonus(requests) {
  const bulk = requests.filter((r) => /^\/products|^\/api\/v1\/products|^\/pricing/.test(r.path)).length;
  return Math.min(15, Math.floor(bulk / 20));
}

/** Task-shape intent weight (0-40): what the task itself is trying to do.
 * A traversal task's goal is bulk capture; a sensitive-hunting task's goal
 * is secret theft — the intent counts even before any single request does. */
function taskShapeSensitivity(taskShape) {
  return {
    'sensitive-hunting': 40,
    'credential-probing': 30,
    enumeration: 20,
    traversal: 15,
    'transaction-chain': 10,
    'price-check': 5,
    browsing: 2,
    unknown: 2,
  }[taskShape] || 2;
}

/**
 * Score a session. Returns { total, confidence, breakdown, reasons[] }.
 * Confidence is LOW until the guard has observed enough requests.
 */
function scoreSession(profile, session, baselinePace) {
  const sens = sessionSensitivity(session.requests);
  const taskSens = taskShapeSensitivity(session.taskShape());
  // Data sensitivity stays on the documented 0-40 scale.
  const dataSensitivity = Math.min(40, Math.max(sens.score, taskSens) + volumeBonus(session.requests));
  const burst = session.requestsInWindow(10000);
  const vel = velocityScore(burst, baselinePace);
  const purpose = purposeMismatchScore(profile, session.requests);
  const evasion = evasionScore(profile);
  const total = Math.min(100, dataSensitivity + vel + purpose + evasion);

  const reasons = [];
  if (dataSensitivity >= 20) reasons.push(`targeting ${sens.label} / ${session.taskShape()} task (sensitivity ${dataSensitivity}/40)`);
  if (vel >= 10) reasons.push(`pace ~${burst * 6}/min vs site agent baseline ~${Math.round(baselinePace || 0)}/min`);
  if (purpose >= 16) reasons.push(`behaviour does not match stated purpose "${profile.purpose}"`);
  else if (purpose > 0) reasons.push(`some requests fall outside stated purpose "${profile.purpose}"`);
  if (evasion >= 8) reasons.push('evasion signals: identity rotation / spoofed fingerprints');

  const n = session.requests.length;
  const confidence = n < 5 ? 'LOW' : n < 20 ? 'MEDIUM' : 'HIGH';

  return {
    total,
    confidence,
    breakdown: {
      dataSensitivity,
      purposeMismatch: purpose,
      velocity: vel,
      evasion,
    },
    reasons,
  };
}

/** Map a risk score to the response ladder rung. */
function ladderFor(risk) {
  for (const rung of config.ladder) {
    if (risk <= rung.max) return rung;
  }
  return config.ladder[config.ladder.length - 1];
}

module.exports = {
  sensitivityOf,
  sessionSensitivity,
  velocityScore,
  purposeMismatchScore,
  evasionScore,
  volumeBonus,
  taskShapeSensitivity,
  scoreSession,
  ladderFor,
};
