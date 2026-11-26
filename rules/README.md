# Community detection rules

Verigus ships with a marketplace of community detection rules: small JSON
files in this directory that add risk when they match a session. Rules are
loaded and validated at guard start; invalid files are reported in
`GET /api/rules` (and on the dashboard) and are not loaded. There is no
hot-reload — restart the guard to pick up rule changes.

## Rule format

```json
{
  "id": "credential-stuffing-burst",
  "name": "Credential stuffing burst",
  "version": 1,
  "author": "verigus-community",
  "description": "Many login attempts in a short window from one agent.",
  "severity": "high",
  "match": {
    "pathPatterns": ["^/login", "^/account/reset"],
    "minRequestsPerMin": 30,
    "userAgentPattern": ".*"
  },
  "risk": 20,
  "action": "boost"
}
```

- `id` — unique, lowercase, dashes only. Required.
- `name` — human-readable name. Required.
- `version` — integer, starting at 1. Required.
- `author` — who wrote the rule. Required.
- `description` — what the rule detects. Optional.
- `severity` — `low`, `medium`, `high`, or `critical`. Required.
- `match` — at least one matcher, all present matchers must match:
  - `pathPatterns` — array of regexes; at least one must match a path
    the session touched.
  - `minRequestsPerMin` — session pace must be at or above this.
  - `userAgentPattern` — regex the agent's user agent must match.
- `risk` — integer 0–30 added to the session's risk when the rule matches.
- `action` — `boost` (add `risk` to the score) or `flag` (record the match
  in the reasons without adding risk).

## Shipped rules

- `credential-stuffing-burst` — many login/reset attempts in a short
  window (+20, boost).
- `api-enumeration` — rapid traversal of the API surface (+15, boost).
- `login-then-sensitive-probe` — login, then a sensitive-path hit (+25,
  boost).

Rules never lift a block and never grant the fast path — they only add
risk and reasons to a session the guard is already scoring.
