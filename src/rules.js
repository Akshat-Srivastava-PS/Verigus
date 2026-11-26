// Marketplace of community detection rules (blueprint Phase 3).
//
// A rule is a JSON file in rules/:
//   {
//     "id": "credential-stuffing-burst",
//     "name": "Credential-stuffing burst",
//     "version": 1,
//     "author": "verigus-community",
//     "description": "...",
//     "severity": "high",
//     "match": {
//       "pathPatterns": ["^/login"],
//       "minRequestsPerMin": 30
//     },
//     "risk": 20,
//     "action": "boost"
//   }
//
// match supports: pathPatterns (regexes over session paths), queryPatterns
// (regexes over the request query string), sequence (ordered path regexes),
// minRequestsPerMin, userAgentPatterns (regexes over the user agent).
// risk is 0–30 and is added to the session score when the rule matches.
// The loader validates every rule (schema + compilable regexes) and
// reports invalid files with reasons instead of crashing the guard.
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_RULES_DIR = path.join(__dirname, '..', 'rules');

function validateRule(raw) {
  const errors = [];
  if (!raw || typeof raw !== 'object') return ['rule must be a JSON object'];
  for (const f of ['id', 'name', 'version', 'match', 'risk']) {
    if (raw[f] === undefined || raw[f] === null) errors.push(`missing "${f}"`);
  }
  if (raw.id && !/^[a-z0-9][a-z0-9-]*$/.test(raw.id)) errors.push('id must be kebab-case');
  if (typeof raw.risk !== 'number' || raw.risk < 0 || raw.risk > 30) errors.push('risk must be a number 0–30');
  if (raw.match && typeof raw.match === 'object') {
    const m = raw.match;
    const hasMatcher = ['pathPatterns', 'queryPatterns', 'sequence', 'minRequestsPerMin', 'userAgentPatterns']
      .some((k) => m[k] !== undefined);
    if (!hasMatcher) errors.push('match must contain at least one matcher');
    for (const k of ['pathPatterns', 'queryPatterns', 'sequence', 'userAgentPatterns']) {
      if (m[k] !== undefined) {
        if (!Array.isArray(m[k])) errors.push(`match.${k} must be an array`);
        else for (const pat of m[k]) {
          try { new RegExp(pat); } catch (e) { errors.push(`match.${k} pattern "${pat}" is not a valid regex`); }
        }
      }
    }
    if (m.minRequestsPerMin !== undefined && typeof m.minRequestsPerMin !== 'number') {
      errors.push('match.minRequestsPerMin must be a number');
    }
  } else if (raw.match !== undefined) {
    errors.push('match must be an object');
  }
  if (raw.action && !['boost', 'flag'].includes(raw.action)) errors.push('action must be "boost" or "flag"');
  return errors;
}

class RuleMarketplace {
  constructor(rulesDir) {
    this.dir = rulesDir || DEFAULT_RULES_DIR;
    this.rules = []; // enabled, validated rules (compiled regexes)
    this.invalid = []; // { file, errors }
    this.load();
  }

  load() {
    this.rules = [];
    this.invalid = [];
    let files = [];
    try { files = fs.readdirSync(this.dir).filter((f) => f.endsWith('.json')).sort(); } catch (_) { return this; }
    for (const file of files) {
      let raw;
      try { raw = JSON.parse(fs.readFileSync(path.join(this.dir, file), 'utf8')); } catch (e) {
        this.invalid.push({ file, errors: [`not valid JSON: ${e.message}`] });
        continue;
      }
      const errors = validateRule(raw);
      if (errors.length) { this.invalid.push({ file, errors }); continue; }
      const compile = (arr) => (arr || []).map((p) => new RegExp(p));
      this.rules.push({
        id: raw.id,
        name: raw.name,
        version: raw.version,
        author: raw.author || 'unknown',
        description: raw.description || '',
        severity: raw.severity || 'medium',
        risk: raw.risk,
        action: raw.action || 'boost',
        match: {
          pathPatterns: compile(raw.match.pathPatterns),
          queryPatterns: compile(raw.match.queryPatterns),
          sequence: compile(raw.match.sequence),
          minRequestsPerMin: raw.match.minRequestsPerMin,
          userAgentPatterns: compile(raw.match.userAgentPatterns),
        },
      });
    }
    return this;
  }

  /** Match enabled rules against a session + the current request. Returns [{ rule, why }]. */
  match(session, { query, userAgent }) {
    const paths = session.requests.map((r) => r.path);
    const hits = [];
    for (const rule of this.rules) {
      const m = rule.match;
      let why = null;
      if (m.pathPatterns.length && paths.some((p) => m.pathPatterns.some((re) => re.test(p)))) {
        why = `path matches rule "${rule.id}"`;
      } else if (m.queryPatterns.length && query && m.queryPatterns.some((re) => re.test(query))) {
        why = `query matches rule "${rule.id}"`;
      } else if (m.userAgentPatterns.length && userAgent && m.userAgentPatterns.some((re) => re.test(userAgent))) {
        why = `user agent matches rule "${rule.id}"`;
      } else if (m.minRequestsPerMin !== undefined && session.requestsPerMin() >= m.minRequestsPerMin) {
        why = `pace ${Math.round(session.requestsPerMin())}/min at or above rule "${rule.id}" threshold`;
      } else if (m.sequence.length) {
        let idx = 0;
        for (const p of paths) {
          if (m.sequence[idx].test(p)) { idx += 1; if (idx === m.sequence.length) { why = `sequence matches rule "${rule.id}"`; break; } }
        }
      }
      if (why) hits.push({ rule, why });
    }
    return hits;
  }

  status() {
    return {
      enabled: this.rules.map((r) => ({ id: r.id, name: r.name, version: r.version, author: r.author, risk: r.risk, action: r.action })),
      invalid: this.invalid,
    };
  }
}

module.exports = { RuleMarketplace, validateRule, DEFAULT_RULES_DIR };
