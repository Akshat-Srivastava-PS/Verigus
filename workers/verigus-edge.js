// Verigus edge worker (blueprint Phase 2) — deploy the guard at the edge.
//
// Cloudflare Workers / any fetch-based edge runtime. The worker asks the
// guard for a decision BEFORE the origin ever sees the request, then
// enforces it. Configure with environment bindings (no secrets in code):
//
//   GUARD_URL  — e.g. https://verigus.onrender.com (your guard deployment)
//                The guard exposes POST /guard/decision for exactly this.
//
//   export default { async fetch(request, env, ctx) { ... } }
//
// Decisions: allow/observe pass through to the origin; challenge and
// throttle answer 429; sandbox serves decoy data; block answers 403 with
// the dossier id. If the guard is unreachable, the worker fails OPEN to
// the origin and logs the outage — the guard never takes a site down.
// (Fail-open is the edge default; set FAIL_CLOSED=true to fail closed.)
'use strict';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const headers = {};
    for (const [k, v] of request.headers.entries()) headers[k.toLowerCase()] = v;

    let decision = null;
    try {
      const res = await fetch(`${env.GUARD_URL.replace(/\/$/, '')}/guard/decision`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method: request.method, path: url.pathname, query: url.search, headers }),
      });
      if (res.ok) decision = await res.json();
    } catch (e) {
      console.log(`[verigus-edge] guard unreachable (${e.message}) — failing open`);
    }
    if (!decision) {
      if (env.FAIL_CLOSED === 'true') {
        return new Response(JSON.stringify({ error: 'guard unavailable' }), { status: 503, headers: { 'content-type': 'application/json' } });
      }
      return fetch(request);
    }

    const outHeaders = { 'content-type': 'application/json', 'x-guard-decision': `${decision.rung} ${decision.action}`, 'x-guard-risk': String(decision.risk) };
    switch (decision.action) {
      case 'allow':
      case 'observe':
        return fetch(request);
      case 'challenge':
        return new Response(JSON.stringify({ error: 'guard challenge', message: 'Prove you are legitimate: present a signed attestation (Web Bot Auth / signed agent card).', risk: decision.risk, reason: decision.reason }), { status: 429, headers: outHeaders });
      case 'throttle':
        outHeaders['retry-after'] = '60';
        return new Response(JSON.stringify({ error: 'throttled by the guard', risk: decision.risk, reason: decision.reason }), { status: 429, headers: outHeaders });
      case 'sandbox':
        return new Response(JSON.stringify({ sandbox: true, products: [{ id: 0, name: 'Decoy Product', price: 0.0 }], note: 'You are in the guard sandbox. This data is decoy.' }), { status: 200, headers: outHeaders });
      case 'block':
        return new Response(JSON.stringify({ error: 'blocked by the guard', risk: decision.risk, reason: decision.reason, dossierId: decision.dossierId || null, note: 'This block is final and permanent. There is no unblock.' }), { status: 403, headers: outHeaders });
      default:
        return fetch(request);
    }
  },
};
