// First-Contact Protocol + Verified Fast Path (blueprint Section 04).
//
// Default for a first-time agent: observe & score — never challenge or block
// on arrival. The one shortcut is the verified fast path, granted only when
// ALL THREE checks pass, and re-checked continuously for the whole session:
//   Check 1 — identity verifies (cryptographic attestation)
//   Check 2 — purpose is authentic, harmless, and permitted here
//   Check 3 — behaviour matches the stated purpose
// Any failure or drift demotes the agent mid-session back to L1
// (observe & score), and the mismatch is recorded on its profile.
//
// DEMO NOTE: real deployments verify Web Bot Auth (Ed25519) signatures or
// signed A2A agent cards against operator-published keys. This working model
// simulates that attestation with an HMAC over (operator, purpose, timestamp)
// using a demo operator key generated fresh at first start — see server.js.
// The check structure (identity + purpose + behaviour) is the real product
// rule; only the signature scheme is a demo stand-in.
'use strict';

const crypto = require('crypto');
const config = require('./config');

/** Verify the agent's presented attestation (demo HMAC stand-in). */
function verifyIdentity(agent, demoOperatorKey) {
  if (!agent.operator || !agent.signature || !agent.signedAt) {
    return { ok: false, reason: 'no identity presented' };
  }
  const expected = crypto
    .createHmac('sha256', demoOperatorKey)
    .update(`${agent.operator}|${agent.purpose || ''}|${agent.signedAt}`)
    .digest('hex');
  // Timing-safe compare on equal-length hex strings.
  let ok = false;
  try {
    ok = crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(agent.signature));
  } catch (_) {
    ok = false;
  }
  if (!ok) return { ok: false, reason: 'signature does not verify against operator keys' };
  if (Date.now() - Number(agent.signedAt) > 15 * 60 * 1000) {
    return { ok: false, reason: 'attestation expired' };
  }
  return { ok: true, reason: 'identity verified' };
}

/** Check 2 — purpose is specific, permitted on this site, and plausible. */
function checkPurpose(agent) {
  if (!agent.purpose) return { ok: false, reason: 'no stated purpose' };
  const purpose = agent.purpose.toLowerCase();
  const permitted = config.permittedPurposes.some((p) => purpose.includes(p));
  if (!permitted) {
    return { ok: false, reason: `purpose "${agent.purpose}" is not a purpose this site permits` };
  }
  if (/general research|anything|whatever/i.test(agent.purpose)) {
    return { ok: false, reason: 'purpose is a vague cover story, not a concrete task' };
  }
  return { ok: true, reason: 'purpose authentic, specific, and permitted' };
}

/** Check 3 — live behaviour stays inside the stated purpose's shape. */
function checkBehaviourMatch(agent, session) {
  if (!agent.purpose) return { ok: false, reason: 'no purpose to match against' };
  const shapes = config.purposeShapes[agent.purpose.toLowerCase()];
  if (!shapes) return { ok: false, reason: 'purpose shape unknown for this site' };
  const outside = session.requests.filter((r) => !shapes.some((re) => re.test(r.path)));
  if (outside.length === 0) return { ok: true, reason: 'behaviour matches stated purpose' };
  return {
    ok: false,
    reason: `behaviour drift: ${outside.length} request(s) outside purpose "${agent.purpose}" (e.g. ${outside[0].path})`,
  };
}

/**
 * Evaluate the fast path for an agent on its current session.
 * Returns { granted, checks: {identity, purpose, behaviour}, reason }.
 */
function evaluateFastPath(agent, session, demoOperatorKey) {
  const identity = verifyIdentity(agent, demoOperatorKey);
  const purpose = checkPurpose(agent);
  const behaviour = checkBehaviourMatch(agent, session);
  const granted = identity.ok && purpose.ok && behaviour.ok;
  return {
    granted,
    checks: { identity, purpose, behaviour },
    reason: granted
      ? 'verified identity + authentic purpose + behaviour match — fast path granted'
      : `fast path denied: ${[identity, purpose, behaviour].filter((c) => !c.ok).map((c) => c.reason).join('; ')}`,
  };
}

/**
 * Continuous re-check: called on every request for an agent currently on
 * the fast path. Returns { stillValid, reason }. A failure demotes the
 * agent to L1 (observe & score) and records the mismatch on its profile.
 */
function recheckFastPath(agent, session, demoOperatorKey) {
  const result = evaluateFastPath(agent, session, demoOperatorKey);
  return { stillValid: result.granted, reason: result.reason, checks: result.checks };
}

module.exports = { verifyIdentity, checkPurpose, checkBehaviourMatch, evaluateFastPath, recheckFastPath };
