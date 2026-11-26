// First-Contact Protocol + Verified Fast Path (blueprint Section 04).
//
// Default for a first-time agent: observe & score — never challenge or block
// on arrival. The one shortcut is the verified fast path, granted only when
// ALL THREE checks pass, and re-checked continuously for the whole session:
//   Check 1 — identity verifies (Web Bot Auth Ed25519, RFC 9421, against
//             operator-published keys; a signed A2A agent card is the
//             second accepted form of identity)
//   Check 2 — purpose is authentic, harmless, and permitted here
//   Check 3 — behaviour matches the stated purpose
// Any failure or drift demotes the agent mid-session back to L1
// (observe & score), and the mismatch is recorded on its profile and in
// the reputation registry.
//
// The v0.1 HMAC attestation stand-in is gone: identity is verified for
// real. The simulator's demo Ed25519 keypair (operator "demo-agent") is
// the only demo fixture left, and it is registered like any operator key.
'use strict';

const config = require('./config');
const webBotAuth = require('./webBotAuth');
const delegation = require('./delegation');

/** Check 1 — identity verifies (Web Bot Auth, or a signed A2A agent card). */
async function verifyIdentity(agent, registry) {
  // Web Bot Auth first.
  const wba = await webBotAuth.verifyWebBotAuth(
    { method: agent.method || 'GET', url: agent.url || '/', headers: agent.headers || {} },
    registry
  );
  if (wba.ok) return { ok: true, method: 'web-bot-auth', operator: wba.operator, reason: wba.reason };
  // A2A agent card second (presented as a decoded card object on the agent).
  if (agent.card) {
    const card = delegation.verifyAgentCard(agent.card, registry);
    if (card.ok) {
      return { ok: true, method: 'a2a-agent-card', operator: card.card.name, reason: card.reason };
    }
    return { ok: false, reason: `A2A card invalid: ${card.reason}; Web Bot Auth also failed: ${wba.reason}` };
  }
  return { ok: false, reason: wba.reason };
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
 * agent: { operator, purpose, method, url, headers, card? }
 * precomputedIdentity (optional): result of verifyIdentity() for this
 * request — the guard computes it once and reuses it for the fast path
 * and the policy checks, so a key is never fetched twice per request.
 * Returns { granted, checks: {identity, purpose, behaviour}, reason }.
 */
async function evaluateFastPath(agent, session, registry, precomputedIdentity) {
  const identity = precomputedIdentity || await verifyIdentity(agent, registry);
  const purpose = checkPurpose(agent);
  const behaviour = checkBehaviourMatch(agent, session);
  const granted = identity.ok && purpose.ok && behaviour.ok;
  return {
    granted,
    checks: { identity, purpose, behaviour },
    reason: granted
      ? `verified identity (${identity.method}) + authentic purpose + behaviour match — fast path granted`
      : `fast path denied: ${[identity, purpose, behaviour].filter((c) => !c.ok).map((c) => c.reason).join('; ')}`,
  };
}

/**
 * Continuous re-check: called on every request for an agent currently on
 * the fast path. Returns { stillValid, reason }. A failure demotes the
 * agent to L1 (observe & score) and records the mismatch on its profile.
 */
async function recheckFastPath(agent, session, registry) {
  const result = await evaluateFastPath(agent, session, registry);
  return { stillValid: result.granted, reason: result.reason, checks: result.checks };
}

module.exports = { verifyIdentity, checkPurpose, checkBehaviourMatch, evaluateFastPath, recheckFastPath };
