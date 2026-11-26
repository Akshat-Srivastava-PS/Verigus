# Verigus — Production Plan (Phases 2 + 3)

Source of truth: blueprint Section 09 "Build roadmap — blueprint to product"
(`~/workspace/your_files/ai-agent-protection-layer-blueprint/ai-agent-protection-layer-blueprint.html`).
The pitch deck is image-only slides (no extractable text); it adds no scope beyond the blueprint.
Live deployment at plan time: ENFORCE, requestsSeen 571, 20 agents, 2 blocked, confidence 0.71
(the demo traffic sim is nearly finished; push only after it settles at ~590+).

## 1. Phase 1 audit — what exists, what is a gap

| Phase 1 item | State | Verdict |
|---|---|---|
| Proxy deployment only | `src/server.js` guards every request before the demo shop | DONE |
| One-line install → observe by default, guard-decided readiness, live ETA + notification | `install.sh`, `src/baseline.js` (confidence-based, ETA, readiness notification wording) | DONE |
| Fingerprinting + risk scoring v1, unsigned-first | `src/guard.js`, `src/scoring.js` (40/25/20/15 weights) | DONE |
| First-Contact Protocol, per-site intent profiles | `src/firstContact.js` (3 checks + demotion) | DONE in structure — **GAP: attestation is a demo HMAC stand-in, not Web Bot Auth** (Phase 2.1) |
| Task Graph v1 (sensitivity first, velocity second) | `src/taskGraph.js` | DONE |
| 3 threat classes: scraping, credential probing, sensitive-path hunting | task shapes + instant-refuse paths | DONE |
| Response ladder L0–L3 + L5 | `src/scoring.js` ladder; L4 sandbox exists in `server.js` | PARTIAL — **GAP: L4 is a single static decoy response, not an interactive decoy mode** (Phase 2.3) |
| Console: live feed, policies, observe mode | feed/status/report/library/dossiers | PARTIAL — **GAP: no policies surface** (Phase 3.3) |
| Threat Library v1 + daily refresh + AgentPulse | `src/threatLibrary.js`, `src/agentpulse.js` | DONE as v1 — **GAPS: indirect prompt injection is a documented pattern with no live match (Phase 2.4); no cross-site filing/merge (Phase 3.1); no reputation registry (Phase 3.2)** |
| 1–3 design-partner sites | Out of scope for code | N/A |

### Phase 1 gaps to fix during this build (not rebuilds)
- **Swarm correlation (documented limitation):** each node is scored on its own record; six agents, one operator, one task reads as six mid-low nodes. Fix via the reputation registry: track operator across fingerprints and score coordinated swarms (Phase 3.2 work).
- **Durable state:** only `blocks.json` persists. Profiles, sessions, baseline, incidents, reputation are in-memory and lost on restart. Fix with a file-backed store (hardening).
- **No health/readiness endpoint; plain `console.log` logging; minimal input validation.** Fix (hardening).
- **No agents.txt / sanctioned door; no edge/gateway deploys; no onboarding provisioning.** Phase 2.5 / 2.6.

## 2. Phase 2 · V1 — build list

### 2.1 Verified fast path, real Web Bot Auth (Ed25519, RFC 9421)
- New `src/webBotAuth.js`: parse `Signature-Input` / `Signature` headers, build the RFC 9421 signature base (`@method`, `@authority`, `@path`, `@query`, `signature-agent`), verify Ed25519 with Node's built-in `crypto` (zero deps). Support `keyid` as a registry key or a fetchable URL (cached, timeout).
- New `src/data/operator-keys.json`: operator → `{ keyid, publicKeyPem, domain }` registry. Server also accepts operator keys from `VERIGUS_OPERATOR_KEYS` env (JSON).
- Rewire `src/firstContact.js`: `verifyIdentity` uses Web Bot Auth; **delete the HMAC path** (keep the demo keypair only for the simulator). Checks 2 (purpose) and 3 (behaviour match + mid-session demotion) unchanged.
- Demo keypair: server generates an Ed25519 keypair at first start, persists the private key to gitignored `.demo-operator-keypair.json`, registers the public key in-memory under operator `demo-agent`. The simulator signs with it. Honest limitation (unchanged from v0.1): the live Render deployment generates its own keypair at first boot, so locally-signed attestations cannot verify against the live deploy — the fast path verifies for real on local runs; document it in README.

### 2.2 Delegated-authority verification
- New `src/delegation.js`: verify AP2-style mandates (`{type:"ap2-mandate", principal, agent, scope, expires_at, signature}` — Ed25519 over canonical JSON, principal key from the registry), Visa TAP payment authorizations (`{type:"tap-payment-authorization", merchant, amount, currency, expires_at, signature}`), and signed A2A agent cards (`{name, url, capabilities, publicKey, signature}` — self-signed card, registry lookup when the operator is known). Presented via `X-Agent-Mandate` / `X-Agent-Card` headers (base64url JSON).
- Transaction endpoints (`POST /api/v1/orders` and any policy-marked transaction) require a valid mandate; invalid/expired/out-of-scope mandate → denied (challenge), logged.

### 2.3 Sandbox / decoy mode (L4), interactive
- New `src/decoy.js`: stateful decoy shop — fake products with plausible-but-wrong prices, fake account/orders, fake API responses; per-fingerprint decoy session; every decoy interaction logged as an incident. Replaces the static one-product decoy in `server.js`.

### 2.4 Prompt-injection (incl. response-side / indirect) + tool-chain detection, live
- New `src/injection.js`: direct-injection pattern set (ignore/disregard instructions, reveal system prompt, role-override, jailbreak markers, `[system]`-style framing) matched live against query params, request body, and headers; indirect detection via scanning site content the agent reads (demo-shop content registry) and requests that echo page text carrying injected instructions; tool-chain rules (read-private-then-send, login→admin→config escalation, bulk-read-then-exfiltrate). Findings feed scoring as a risk boost + reasons + incidents.
- Threat Library entries for these behaviours gain live `contentPatterns` / `sequence` matches (the `indirect-prompt-injection` entry's note is updated: detection is now wired in).

### 2.5 Published agent contract (agents.txt-style) + sanctioned API/MCP door
- `GET /agents.txt`: published contract — allowed agents, permitted purposes, allowed/blocked endpoints, rate limits, auth (Web Bot Auth), MCP door URL.
- `GET /api/agent` (JSON-RPC 2.0): `tools/list` (sanctioned tools: `list_products`, `search_products`, `get_order_status` — the last requires a valid mandate) and `tools/call` (validated params, executed against demo-shop data; the HTTP request itself still passes through the guard).

### 2.6 Edge worker + gateway plugin deploys; self-serve onboarding
- `workers/verigus-edge.js`: Cloudflare-Workers-style edge adapter — calls the guard decision API and enforces allow/challenge/block before the origin.
- New `POST /guard/decision` endpoint: returns the guard decision for a request descriptor `{method, path, headers}` (the integration point edge/gateway call).
- New `src/gatewayPlugin.js`: `createGuardMiddleware(guard)` — a requireable Node `http` middleware wrapping any handler with guard decisions.
- New `scripts/onboard.js` (`npm run onboard -- --site myshop.example.com`): generates a site id + Ed25519 keypair + `verigus.site.json` config and prints the one-line install, the Render Blueprint snippet, and the dashboard URL. `install.sh` points at it.

## 3. Phase 3 · Platform — build list

### 3.1 Cross-site threat-intelligence network
- New `src/intel.js`: `POST /v1/intel/report` ingest — strict schema validation, PII stripping (drops IPs, raw user-agents, cookies), pending store; `dailyRefresh` merges pending findings into the library (dedupe by pattern hash, corroboration counting, source `verigus-network`, version bump); `GET /v1/intel/status`. Single-site deployment works standalone with zero peers; the network part is the filing/ingest protocol + merge logic.

### 3.2 Agent reputation registry
- New `src/reputation.js` (file-backed via the store): identity (operator or fingerprint) → `{ firstSeen, lastSeen, requests, purposeMismatches: [{at, purpose, drift}], demotions, blocks, breakingChangeRechecks, score }`. Score starts neutral 50; mismatch −10, demotion −15, block −50. Registry feeds scoring (score < 30 adds +10 risk; < 10 adds +15) and the breaking-change re-check records outcomes here.
- Operator-level swarm correlation: fingerprints sharing an operator accumulate a joint risk signal; a coordinated swarm (≥4 nodes, one operator, one task shape) boosts each node's risk.
- Existing AgentPulse breaking-change re-check trigger kept and extended: re-check results are recorded in the registry.

### 3.3 Per-endpoint and per-transaction policies
- New `src/policies.js` + `src/data/policies.json`: endpoint patterns → `{ allowedPurposes, maxRisk, requireVerified, requireMandate, transactions }`. Enforced in `guard.handle` before the ladder; violations raise risk / deny with a reason. Dashboard gets a Policies section; `GET /api/policies` exposes the active policy set (read-only).

### 3.4 Data-integrity watch
- New `src/integrity.js`: SHA-256 content registry for site content (products/pricing at boot + on a 60 s re-check); unexpected change → incident + risk event (poisoning). Disguised-exfiltration detection: large base64/hex payloads in query/body, sensitive-field volume in responses. Findings feed scoring.

### 3.5 Compliance reports + SIEM integrations
- New `src/audit.js`: structured JSON logging (`log(level, event, fields)`), append-only JSONL audit log (`src/data/audit.jsonl`, capped), event capture (decisions, blocks, fast-path grants/demotions, policy denials, integrity findings, intel filings, re-checks).
- `GET /api/compliance/report`: JSON compliance report (period counts, blocks + dossiers, policy coverage, library version, feed health, retention note). Dashboard Compliance section renders it. `GET /api/audit/export`: audit-log JSON export.
- SIEM forwarding: `SIEM_WEBHOOK_URL` env — block/incident events POSTed as JSON (fire-and-forget, timeout, failure logged not fatal); optional HMAC signature header when `SIEM_WEBHOOK_SECRET` is set.

### 3.6 Marketplace of community detection rules
- New `src/rules.js` + `rules/` directory: rule format JSON `{id, name, version, author, description, severity, match: {pathPatterns?, queryPatterns?, sequence?, minRequestsPerMin?, userAgentPatterns?}, risk}`. Loader validates schema (required fields, match shape, risk 0–30), enables valid rules, reports invalid ones with reasons. Guard applies enabled rules as extra scoring signals (risk boost + reason). Ship 3 sample rules. `GET /api/rules` lists rules + status; dashboard Rules section.

## 4. Production-ready hardening

- **Durable state** — new `src/store.js`: single file-backed store `src/data/state.json` (blocks, dossiers, reputation, baseline, incidents, intel pending). Atomic write (tmp + rename), debounced saves, load with validation + corrupt-file quarantine. Guard's `blocks.json` migrates in on first load. Baseline gains `serialize()/restore()`. **Documented limitation:** Render's free-tier ephemeral filesystem still resets on redeploy — README documents the production step (Render persistent disk mounted at `src/data`, or a `DATABASE_URL` Postgres adapter behind the same store interface) without switching the live deployment to a paid plan.
- **Health/readiness** — `GET /healthz` (liveness), `GET /readyz` (library loaded + feed status).
- **Structured logging** — JSON lines via `src/audit.js`; replace ad-hoc `console.log` in the request path.
- **Input validation** — URL length cap (2048), header count/size caps, POST body cap (64 KB), JSON parse errors → 400, schema validation on intel/mandate/card payloads.
- **No secrets** in code/README/tests; no invented market/pricing/funding figures anywhere.
- **README** — rewrite: install, production deploy notes (Render + persistent-disk/Postgres step), architecture (new modules), agent contract, rules format, compliance/SIEM, honest limitations.
- **Dashboard** — new sections: Reputation, Policies, Integrity watch, Compliance, Agent contract, Intel network, Rules.
- **Simulator** — new personas: Web Bot Auth verified AgentPulse (Ed25519), direct + indirect injection attacker, tool-chain attacker (read-then-send), mandate agent (valid mandate succeeds, expired mandate denied), decoy driver (pushes to L4, interacts with decoy), shared-operator swarm (correlation boost). Existing personas kept.
- **Tests** — extend `test/guard.test.js`, add `test/production.test.js`: Web Bot Auth (valid/tampered/expired/wrong key), delegation (valid/expired/out-of-scope/tampered mandate + TAP + A2A card), policies, reputation + persistence round-trip, intel ingest + merge, integrity (hash change + exfiltration pattern), injection (direct/indirect/tool-chain), rules loader (valid/invalid), store save/load, health endpoints. `npm test` green throughout.

## 5. Hard constraints (unchanged)
Observe-first; weights 40/25/20/15; fast path only identity + authentic behaviour-matched purpose, re-checked every request, mid-session demotion; blocks FINAL — no unblock/allowlist/override anywhere; dashboard read-only; guard-decided ETA + notification; two-part learning report with findings carried into enforcement; daily Threat Library refresh; AgentPulse stays the integrated feed. No touching the AgentPulse repo/service. No new GitHub repos. Live Render service stays on the free plan.

## 6. Delivery order
1. This plan. 2. Store/audit/logging/health plumbing. 3. Web Bot Auth + firstContact rewire. 4. Delegation + policies. 5. Injection + integrity. 6. Decoy L4. 7. Agent contract + edge/gateway/onboard. 8. Reputation + intel + library merge. 9. Rules marketplace. 10. Compliance/SIEM/audit endpoints + dashboard. 11. Baseline persistence. 12. README/install. 13. Tests + local e2e (`npm run simulate`, `simulate:breaking-change`). 14. Push (snapshot-push procedure; verify head still `eb6109e8…` first; only after live sim settles ~590+). 15. Wait for Render auto-deploy, verify live, report.
