// Blocked-agent dossier (blueprint Section 06).
// A block is never just a log line: the dossier is the full picture behind
// every block — identity & operator, origin, domain, stated purpose, the
// reason tied to its score and behaviour, and the full supporting stats.
//
// READ-ONLY: the dossier contains no unblock or override control, for any
// agent, ever. Exporting it (JSON) for an incident report is the only
// action an owner can take.
'use strict';

function buildDossier({ agent, profile, session, score, ladder, libraryHits, blockedAt }) {
  const paths = session.requests.map((r) => r.path);
  const dataTargeted = [];
  if (paths.some((p) => /^\/(\.env|\.git|config|backup|admin)/.test(p))) {
    dataTargeted.push('Sensitive files: /.env, /config, /.git, backup paths');
  }
  const catalogHits = paths.filter((p) => /^\/products/.test(p)).length;
  if (catalogHits > 0) dataTargeted.push(`Full pricing/catalog export shape: ${catalogHits} product pages in traversal order`);
  if (paths.some((p) => /^\/account/.test(p))) {
    dataTargeted.push('Account-shaped data: /account and reset-flow endpoints probed');
  }
  if (paths.some((p) => /^\/api\/v1\//.test(p))) {
    dataTargeted.push(`Undocumented API paths: ${paths.filter((p) => /^\/api\/v1\//.test(p)).length} hits (enumeration)`);
  }

  return {
    // URL-safe id: fingerprint slices can contain '|' and other characters
    // that break the /api/dossier/:id route, so strip non-word characters.
    id: `dossier-${Date.now()}-${profile.fingerprint.slice(0, 8).replace(/[^\w-]/g, '')}`,
    verdict: 'BLOCKED',
    ladder: ladder.rung,
    risk: score.total,
    confidence: score.confidence,
    blockedAt: blockedAt || new Date().toISOString(),
    companyOperator: agent.operator || 'Unattributed — no verified operator',
    identityNote: agent.identityVerified
      ? `Identity verified for operator "${agent.operator}".`
      : 'No verifiable identity presented. Any claimed name in headers could not be verified against operator keys — treated as a claim, not an identity.',
    countryOfOrigin: profile.country || 'Unknown (demo traffic is local)',
    domain: agent.domain || 'No agent domain — direct traffic',
    statedPurpose: agent.purpose || '(none stated)',
    purposeAssessment: profile.purposeMismatch
      ? `Stated purpose "${agent.purpose}" does not explain the observed behaviour.`
      : 'No purpose was stated; behaviour was judged on its own record.',
    identityAndFastPath: agent.fastPathGranted
      ? 'Was on the verified fast path; demoted after purpose/behaviour mismatch.'
      : 'Unsigned · never fast-path eligible.',
    sessionSummary: {
      requests: session.requests.length,
      durationSeconds: Math.round((Date.now() - session.startedAt) / 1000),
      endpointsTouched: [...new Set(paths)],
      taskShape: session.taskShape(),
    },
    whyBlocked: score.reasons.length
      ? score.reasons.join('; ') + '.'
      : 'Observed task did not match any legitimate purpose.',
    scoreBreakdown: {
      dataSensitivity: `${score.breakdown.dataSensitivity}/40`,
      behaviourVsStatedPurpose: `${score.breakdown.purposeMismatch}/25`,
      velocityAnomaly: `${score.breakdown.velocity}/20`,
      evasionSignals: `${score.breakdown.evasion}/15`,
      total: `${score.total}/100`,
    },
    dataTargeted,
    speedAndPattern: {
      requestsPerMin: Math.round(session.requestsPerMin()),
      siteAgentBaselineP95: profile.baselineP95 ? Math.round(profile.baselineP95) : null,
      identityRotations: profile.identityRotations,
    },
    libraryMatches: libraryHits.map((h) => ({ id: h.entry.id, name: h.entry.name, why: h.why })),
    readOnly: true,
    unblockAvailable: false,
    note: 'This dossier is read-only. There is deliberately no unblock action here — a block is final and permanent.',
  };
}

module.exports = { buildDossier };
