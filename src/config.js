// Central configuration for the Verigus working model.
// Everything is overridable with environment variables. No secrets live here:
// the demo operator key is generated fresh at first start (see server.js)
// and stored in a gitignored local file.
'use strict';

module.exports = {
  // Port the guard + demo site listen on.
  port: parseInt(process.env.PORT || '3000', 10),

  // AgentPulse — the integrated outage-intelligence feed. This is Akshat's
  // live service; /v1/metrics was verified live on 2026-11-26 returning real
  // JSON (37 services, active incidents, breaking-change counts).
  agentPulseBaseUrl: process.env.AGENTPULSE_BASE_URL || 'https://agentpulse-43di.onrender.com',
  agentPulseFeedPath: '/v1/metrics',
  agentPulsePollSeconds: parseInt(process.env.AGENTPULSE_POLL_SECONDS || '300', 10),

  // Data-sensitivity map: path patterns -> sensitivity score (0-40 scale).
  // Data sensitivity is weighted FIRST in scoring; velocity second.
  sensitivity: [
    { pattern: /^\/(\.env|\.git|config|backup|admin)/, score: 40, label: 'sensitive file / admin path' },
    { pattern: /^\/account/, score: 20, label: 'account-shaped data' },
    { pattern: /^\/login/, score: 20, label: 'auth endpoint' },
    { pattern: /^\/api\/v1\//, score: 15, label: 'API endpoint' },
    { pattern: /^\/pricing/, score: 8, label: 'pricing data' },
    { pattern: /^\/products/, score: 5, label: 'catalog data' },
    { pattern: /^\/search/, score: 5, label: 'search / catalog data' },
    { pattern: /^\//, score: 2, label: 'public content' },
  ],

  // Response-ladder thresholds (risk 0-100), per the blueprint Section 04.
  ladder: [
    { max: 20, rung: 'L0', action: 'allow' },
    { max: 40, rung: 'L1', action: 'observe' },
    { max: 60, rung: 'L2', action: 'challenge' },
    { max: 75, rung: 'L3', action: 'throttle' },
    { max: 89, rung: 'L4', action: 'sandbox' },
    { max: 100, rung: 'L5', action: 'block' },
  ],

  // Observe-mode readiness: the guard decides when the baseline is solid.
  // No fixed period. Readiness needs a minimum sample and stable patterns.
  baseline: {
    minRequests: parseInt(process.env.BASELINE_MIN_REQUESTS || '150', 10),
    minAgents: parseInt(process.env.BASELINE_MIN_AGENTS || '5', 10),
    // Estimated requests needed before the guard can judge readiness.
    targetRequests: parseInt(process.env.BASELINE_TARGET_REQUESTS || '300', 10),
  },

  // Threat Library refresh cadence: daily (86_400_000 ms).
  libraryRefreshMs: 24 * 60 * 60 * 1000,

  // Paths the guard treats as unambiguously hostile on their own
  // (the narrow exception to observe-first): instant refusal.
  instantRefusePaths: [
    /^\/\.env/,
    /^\/\.git/,
    /^\/config(\/|$)/,
    /^\/\.aws\//,
    /^\/backup/i,
  ],

  // Purposes this demo site permits for the verified fast path.
  // A purpose must be specific, plausible, and belong to the operator.
  permittedPurposes: [
    'price comparison',
    'product research',
    'order-status lookup',
    'search indexing',
  ],

  // Endpoint shapes each permitted purpose is allowed to touch.
  // Behaviour outside the shape breaks the purpose match (Check 3).
  purposeShapes: {
    'price comparison': [/^\/products/, /^\/pricing/, /^\/search/, /^\/$/],
    'product research': [/^\/products/, /^\/search/, /^\/$/],
    'order-status lookup': [/^\/api\/v1\/orders/, /^\/account/],
    'search indexing': [/^\/products/, /^\/search/, /^\/$/],
  },

  // Demo site identity.
  siteName: process.env.SITE_NAME || 'shop.example.com',
};
