// Gateway plugin (blueprint Phase 2): the guard as requireable middleware.
//
// Any Node.js http server can put Verigus in front of its own routes:
//
//   const { Guard } = require('verigus/src/guard');
//   const { createGuardMiddleware } = require('verigus/src/gatewayPlugin');
//   const guard = new Guard({ library, agentPulse, registry });
//   const server = http.createServer((req, res) => {
//     createGuardMiddleware(guard)(req, res, () => myApp(req, res));
//   });
//
// Decisions mirror the built-in server exactly: allow/observe pass the
// request through (next()), challenge and throttle answer 429, sandbox
// serves the interactive decoy, block answers 403 with the dossier id.
// Blocks stay final — there is no unblock, allowlist, or override here
// either. The middleware never mutates the guard's verdicts; it only
// renders them.
'use strict';

const { DecoySession } = require('./decoy');

/** Render a guard decision into an HTTP response. Returns true when answered. */
function applyDecision(req, res, decision, { decoySession } = {}) {
  const sendJson = (status, obj, extraHeaders) => {
    const body = JSON.stringify(obj, null, 2);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...(extraHeaders || {}) });
    res.end(body);
  };
  res.setHeader('X-Guard-Decision', `${decision.rung} ${decision.action}`);
  res.setHeader('X-Guard-Risk', String(decision.risk));
  switch (decision.action) {
    case 'allow':
    case 'observe':
      return false; // caller continues to the origin handler
    case 'challenge':
      sendJson(429, {
        error: 'guard challenge',
        message: 'Prove you are legitimate: present a signed attestation (Web Bot Auth / signed agent card).',
        risk: decision.risk, reason: decision.reason,
      });
      return true;
    case 'throttle':
      sendJson(429, { error: 'throttled by the guard', risk: decision.risk, reason: decision.reason }, { 'Retry-After': '60' });
      return true;
    case 'sandbox': {
      const decoy = decoySession || new DecoySession(decision.fingerprint || 'gateway');
      sendJson(200, { ...decoy.serve(req), note: 'You are in the guard sandbox. This data is decoy.' });
      return true;
    }
    case 'block':
      sendJson(403, {
        error: 'blocked by the guard',
        risk: decision.risk,
        reason: decision.reason,
        dossierId: decision.dossierId || null,
        note: 'This block is final and permanent. There is no unblock.',
      });
      return true;
    default:
      return false;
  }
}

/**
 * Build a (req, res, next) middleware around a Guard instance.
 * Options: { onDecision(decision, req) } — observability hook (logging, metrics).
 */
function createGuardMiddleware(guard, options) {
  const opts = options || {};
  const decoys = new Map(); // fingerprint -> DecoySession
  return function guardMiddleware(req, res, next) {
    const url = new URL(req.url || '/', 'http://localhost');
    req.path = url.pathname;
    const decision = guard.handle(req);
    if (opts.onDecision) {
      try { opts.onDecision(decision, req); } catch (_) { /* observability must never break the guard */ }
    }
    let decoySession = null;
    if (decision.action === 'sandbox') {
      const fp = decision.fingerprint || 'gateway';
      if (!decoys.has(fp)) decoys.set(fp, new DecoySession(fp));
      decoySession = decoys.get(fp);
    }
    const answered = applyDecision(req, res, { ...decision, fingerprint: decision.fingerprint }, { decoySession });
    if (!answered && typeof next === 'function') next();
  };
}

module.exports = { applyDecision, createGuardMiddleware };
