// Per-endpoint and per-transaction policies (blueprint Phase 3).
//
// Policies are data, not code: src/data/policies.json maps endpoint
// patterns to what the guard enforces there — which purposes may use it,
// the risk ceiling, whether a verified identity is required, and whether
// a delegated-authority mandate is required (transactions).
// The guard checks policies before the response ladder; a violation raises
// the risk and, for transactions without a mandate, denies outright.
// The active policy set is read-only and visible at GET /api/policies.
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_POLICIES_PATH = path.join(__dirname, 'data', 'policies.json');

function loadPolicies(policiesPath) {
  const p = policiesPath || DEFAULT_POLICIES_PATH;
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!raw || !Array.isArray(raw.endpoints)) throw new Error('policies file must have an "endpoints" array');
    const endpoints = raw.endpoints.map((e) => ({
      pattern: e.pattern,
      regex: new RegExp(e.pattern),
      methods: (e.methods || ['GET']).map((m) => String(m).toUpperCase()),
      allowedPurposes: e.allowedPurposes || null,
      maxRisk: typeof e.maxRisk === 'number' ? e.maxRisk : 100,
      requireVerified: !!e.requireVerified,
      requireMandate: !!e.requireMandate,
      transactions: !!e.transactions,
      description: e.description || '',
    }));
    return { version: raw.version || 1, endpoints, raw };
  } catch (err) {
    // No policies file (or a broken one): fall back to the built-in
    // transaction guard — orders still require a mandate.
    return {
      version: 0,
      endpoints: [{
        pattern: '^/api/v1/orders',
        regex: /^\/api\/v1\/orders/,
        methods: ['GET', 'POST'],
        allowedPurposes: ['order-status lookup'],
        maxRisk: 40,
        requireVerified: false,
        requireMandate: true,
        transactions: true,
        description: 'Built-in fallback: order transactions require a delegated mandate.',
      }],
      raw: null,
      loadError: String(err.message || err),
    };
  }
}

/** Find the policy covering this method + path (first match wins). */
function policyFor(policies, method, requestPath) {
  if (!policies || !Array.isArray(policies.endpoints)) return null;
  return policies.endpoints.find((e) => e.methods.includes(String(method || 'GET').toUpperCase()) && e.regex.test(requestPath)) || null;
}

/**
 * Check a request against its policy.
 * ctx: { agent: {purpose, identityVerified}, mandate: verified mandate or null, risk }
 * Returns { allowed, violations: [strings], requiresMandate }
 */
function checkPolicy(policy, ctx) {
  if (!policy) return { allowed: true, violations: [], requiresMandate: false };
  const violations = [];
  if (policy.allowedPurposes && ctx.agent && ctx.agent.purpose) {
    const p = String(ctx.agent.purpose).toLowerCase();
    if (!policy.allowedPurposes.some((a) => p.includes(String(a).toLowerCase()))) {
      violations.push(`purpose "${ctx.agent.purpose}" is not allowed on ${policy.pattern}`);
    }
  }
  if (policy.requireVerified && ctx.agent && !ctx.agent.identityVerified) {
    violations.push(`endpoint ${policy.pattern} requires a verified identity`);
  }
  if (typeof ctx.risk === 'number' && ctx.risk > policy.maxRisk) {
    violations.push(`risk ${ctx.risk} exceeds the policy ceiling ${policy.maxRisk} for ${policy.pattern}`);
  }
  const requiresMandate = !!policy.requireMandate;
  if (requiresMandate && !ctx.mandate) {
    violations.push(`endpoint ${policy.pattern} requires a delegated-authority mandate`);
  }
  return { allowed: violations.length === 0, violations, requiresMandate };
}

module.exports = { loadPolicies, policyFor, checkPolicy, DEFAULT_POLICIES_PATH };
