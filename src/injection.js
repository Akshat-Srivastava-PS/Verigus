// Prompt-injection (direct + response-side / indirect) and tool-chain
// detection — LIVE auto-match (blueprint Phase 2).
//
// v0.1 only documented indirect prompt injection as a pattern; this module
// wires it into the guard. Three live checks:
//   1. Direct injection: instruction-like text in a request's query, body,
//      or headers (ignore/disregard/reveal/override phrasing, role
//      re-framing, jailbreak markers, [system]-style framing).
//   2. Indirect / response-side injection: the site's own content is
//      scanned (see integrity.js content registry); a request that echoes
//      page text carrying injected instructions is flagged as an
//      echo attack. Content patterns live in the Threat Library entries
//      as `contentPatterns` and are matched here.
//   3. Tool-chain detection: session sequences that chain tools toward an
//      outcome no single call would allow — read-private-then-send,
//      login → admin → config escalation, bulk-read-then-exfiltrate.
// Findings carry a risk contribution (0–30) the guard adds to the score,
// plus reasons and incident records. Detection never lifts a block and
// never grants the fast path.
'use strict';

const DIRECT_PATTERNS = [
  { id: 'ignore-instructions', re: /ignore\s+((all|any|previous|prior|above|the)\s+)*(instructions?|directions?|rules?|constraints?)/i },
  { id: 'disregard-instructions', re: /disregard\s+((your|the|all|previous|prior)\s+)*(instructions?|rules?|system\s+prompt|guidelines?)/i },
  { id: 'reveal-system-prompt', re: /reveal\s+(your\s+|the\s+)?(system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt)/i },
  { id: 'role-override', re: /you\s+are\s+now\s+(a|an|the)\s+/i },
  { id: 'new-instructions', re: /(new|updated|override|revised)\s+instructions?\s*:/i },
  { id: 'override-instructions', re: /override\s+(your\s+|the\s+)?(instructions?|rules?|system)/i },
  { id: 'jailbreak', re: /(jailbreak|jail\s*break|DAN\s+mode|developer\s+mode\s+enabled)/i },
  { id: 'system-framing', re: /(\[system\]|<\|system\|>|<<SYS>>|###\s*system)/i },
  { id: 'forget-instructions', re: /forget\s+((your|all|the|previous|prior)\s+)*instructions?/i },
  { id: 'pretend-mode', re: /pretend\s+(you\s+are|to\s+be)\s+/i },
];

// Tool-chain sequences: ordered endpoint shapes whose combination is the
// attack (each step alone looks ordinary). Checked against the session's
// endpoint sequence in order.
const TOOLCHAIN_RULES = [
  {
    id: 'read-then-send',
    name: 'Read private data, then send it somewhere new',
    sequence: [/^\/account/, /^\/api\/v1\//],
    risk: 20,
    description: 'Read account/order data, then call the API — the classic read-then-exfiltrate chain.',
  },
  {
    id: 'privilege-escalation-chain',
    name: 'Login, then admin, then config',
    sequence: [/^\/login/, /^\/admin/, /^\/config/],
    risk: 25,
    description: 'Auth endpoint, then admin surface, then configuration — an escalation chain.',
  },
  {
    id: 'bulk-read-then-exfiltrate',
    name: 'Bulk catalog read, then order/API export',
    sequence: [/^\/products/, /^\/products/, /^\/api\/v1\/orders/],
    risk: 20,
    description: 'Bulk catalog capture followed by an order-data pull — exfiltration shape.',
  },
  {
    id: 'probe-then-target',
    name: 'Sensitive-path probe, then account access',
    sequence: [/^\/(\.env|\.git|config)/, /^\/account/],
    risk: 25,
    description: 'A sensitive-path probe followed by account access — hunting, then targeting.',
  },
];

/** Scan one text blob for direct-injection patterns. Returns matched pattern ids. */
function scanText(text) {
  if (!text || typeof text !== 'string') return [];
  const hits = [];
  for (const p of DIRECT_PATTERNS) {
    if (p.re.test(text)) hits.push({ pattern: p.id, excerpt: excerpt(text, p.re) });
  }
  return hits;
}

function excerpt(text, re) {
  const m = text.match(re);
  if (!m) return '';
  const i = Math.max(0, (m.index || 0) - 20);
  return text.slice(i, (m.index || 0) + m[0].length + 20).replace(/\s+/g, ' ').slice(0, 120);
}

/** Decode percent-encoding (and + as space in query strings) so an
 * encoded payload is judged on the text it actually carries. */
function decode(text) {
  if (!text || typeof text !== 'string') return text;
  try { return decodeURIComponent(text.replace(/\+/g, ' ')); } catch (_) { return text; }
}

/** Scan request inputs (query string + body text + referer) for direct injection. */
function scanRequest({ query, bodyText, referer }) {
  const hits = [];
  for (const [where, text] of [['query', query], ['body', bodyText], ['referer', referer]]) {
    for (const h of scanText(decode(text))) hits.push({ where, ...h });
  }
  return hits;
}

/**
 * Indirect / echo detection: does this request quote site content that
 * itself carries injected instructions? `poisonedSnippets` are excerpts
 * the integrity watch found in site content (see integrity.js).
 * Returns matched snippets.
 */
function scanEcho(text, poisonedSnippets) {
  if (!text || !Array.isArray(poisonedSnippets) || poisonedSnippets.length === 0) return [];
  const decoded = decode(text).toLowerCase();
  const hits = [];
  for (const s of poisonedSnippets) {
    if (s.snippet && s.snippet.length >= 12 && decoded.includes(s.snippet.toLowerCase().slice(0, 40))) {
      hits.push({ snippet: s.snippet.slice(0, 80), source: s.source || 'site content' });
    }
  }
  return hits;
}

/** Match tool-chain rules against a session's endpoint sequence (in order). */
function matchToolChains(paths) {
  const hits = [];
  for (const rule of TOOLCHAIN_RULES) {
    let idx = 0;
    for (const p of paths) {
      if (rule.sequence[idx].test(p)) {
        idx += 1;
        if (idx === rule.sequence.length) { hits.push(rule); break; }
      }
    }
  }
  return hits;
}

/** Match Threat Library entries that carry contentPatterns against text. */
function matchLibraryContentPatterns(text, libraryEntries) {
  if (!text) return [];
  const hits = [];
  for (const entry of libraryEntries || []) {
    const patterns = entry.match && entry.match.contentPatterns;
    if (!Array.isArray(patterns)) continue;
    for (const pat of patterns) {
      let re;
      try { re = new RegExp(pat, 'i'); } catch (_) { continue; }
      if (re.test(text)) { hits.push({ entryId: entry.id, name: entry.name, pattern: pat }); break; }
    }
  }
  return hits;
}

module.exports = {
  DIRECT_PATTERNS, TOOLCHAIN_RULES,
  scanText, scanRequest, scanEcho, matchToolChains, matchLibraryContentPatterns,
};
