# Verigus — AI Agent Protection Layer

> **Every agent verified, every threat remembered.**

An AI protection layer that sits in front of a website — before traffic ever
touches the origin — watching for other AI agents trying to probe, steal, or
break things, and reacting on its own. Not another crawler blocker: this one
is built for the agents nobody else can handle — the unsigned, undeclared
majority — and judges the whole task they're carrying out, not single
requests.

This repository is the **production build (v0.2.0)** of the product defined
in the product blueprint developed alongside it (blueprint, market research,
and stakeholder pitch deck in Akshat's Drive). It implements the blueprint's
Phase 1, Phase 2, and Phase 3 end to end, against a small demo shop included
in the repo. Phase 1 was the working model (v0.1); this version is the
production-ready build on top of it.

## What it does

- **Guard at the edge** — every request to the demo site passes through the
  guard first (`src/guard.js`). The origin only ever sees traffic the guard
  has cleared.
- **Observe first** — the guard starts in OBSERVE mode after install. It
  learns the site's normal traffic before ever blocking anything. Readiness
  is the guard's own decision (confidence-based, no fixed period) and it
  reports a live ETA — in the dashboard and as a notification — using the
  blueprint's exact readiness wording. When ready, it attaches a learning
  report: Part 1, the normal patterns it learned; Part 2, the suspicious
  things it noticed, each paired with the reaction it now applies.
- **Task-level scoring** — the Task Graph Engine links requests across
  endpoints into one task and scores the task, not the request. **Data
  sensitivity is weighted first, call velocity second** (dossier breakdown:
  data sensitivity 0–40, behaviour vs. stated purpose 0–25, velocity 0–20,
  evasion 0–15).
- **First-Contact Protocol** — unknown agents are watched and scored. The
  only shortcut is the **verified fast path**: verified identity AND an
  authentic, harmless, behaviour-matched purpose. Identity alone earns
  nothing. The fast path is re-checked every request; any drift demotes the
  agent mid-session back to observe-and-score.
- **Verified fast path, real** — identity is proven with real Web Bot Auth
  (Ed25519 HTTP Message Signatures, RFC 9421) against operator-published
  keys, or with a signed A2A agent card. The v0.1 HMAC attestation stand-in
  is gone. A demo Ed25519 keypair is generated at first start for the
  simulator (see "How the fast path is verified" below).
- **Delegated authority** — before an agent may act on a customer's behalf
  (e.g. place an order), the guard verifies its delegated authority: an
  AP2-style mandate, a Visa TAP payment authorization, or a signed A2A
  agent card. A transaction without a valid mandate is denied once the
  guard is enforcing.
- **Response ladder** — L0 allow, L1 observe & score, L2 challenge, L3
  throttle, L4 sandbox (interactive decoy data — a consistent fake shop per
  agent, never real data), L5 block & report. One narrow exception: a direct
  hit on a known sensitive path (`/.env`, `/.git`, `/config`) is refused
  instantly, even in observe mode.
- **Blocks are final and permanent.** There is deliberately no unblock
  method, no allowlist-after-the-fact, and no override anywhere in the code
  or the dashboard. The owner dashboard is read-only visibility.
- **Blocked-agent dossier** — every block opens a full dossier: company /
  operator, country, domain, stated purpose, why it was blocked with a score
  breakdown, data targeted, speed and pattern, endpoints touched.
- **Threat Library** — the guard's own living record of suspicious AI-agent
  activity and agent-related outages, seeded from documented research
  (the top 10 behaviours from the 26 Nov 2026 research pass — indirect
  prompt injection, tool poisoning, exfiltration via benign channels,
  spoofed/stealth identity, unsafe tool chaining, admin/internal/SSRF
  probing, rug-pull/change detection, credential harvesting, loop/fan-out /
  token-burning, scope drift — plus the blueprint's threat taxonomy).
  It refreshes **daily** on a fixed schedule: collect, verify &
  de-duplicate, convert to detection, push to every guard.
- **AgentPulse, integrated** — the outage side of the library is powered by
  [AgentPulse](https://agentpulse-43di.onrender.com) (Akshat's live
  API/cloud status oracle: real Statuspage ingestion across 37 services).
  The guard polls its live `/v1/metrics` endpoint (verified live
  2026-11-26). When AgentPulse flags a breaking change in a dependency's
  API, the guard immediately re-scores and re-verifies every agent touching
  that dependency — it does not wait for the next daily update. If the feed
  is unreachable, the guard keeps working on its seeded library and logs it.
- **Prompt-injection & tool-chain detection, live** — direct injection
  patterns in query/body/referer are auto-matched (and URL-decoded first,
  so encoded payloads are judged on the text they carry); indirect
  injection is detected when a request echoes site content carrying an
  injected instruction; tool-chain rules flag sequences such as
  read-private-then-send and login → admin → config.
- **Published agent contract** — `/agents.txt` states the contract for
  agents (allowed/disallowed paths, authentication, rate limits, the MCP
  door), and `POST /api/agent` is the sanctioned JSON-RPC 2.0 (MCP) door:
  `tools/list`, `tools/call` for `list_products`, `search_products`,
  `get_order_status` (the last requires a verified mandate). The door still
  passes through the guard like any other request.
- **Per-endpoint & per-transaction policies** — `src/data/policies.json`
  (first match wins): allowed purposes, max risk, `requireVerified`,
  `requireMandate`, transaction rules. `/api/v1/orders` requires a mandate
  and caps risk; a policy violation adds risk and, once enforcing, denies
  the transaction.
- **Agent reputation registry** — every identity carries a score (50
  neutral) with recorded purpose-mismatch history, demotions, fast-path
  grants, and blocks. A low score adds risk to every future request.
  **Coordinated swarms are correlated by operator**: four or more nodes
  from one operator running one task shape add a swarm boost.
- **Data-integrity watch** — site content is hashed at start and re-checked
  every minute; an unapproved change is a poisoning signal. Requests
  carrying disguised exfiltration shapes (long base64/hex blobs, sensitive
  field names) are flagged.
- **Cross-site threat-intelligence network** — protected sites file
  anonymised findings at `POST /v1/intel/report` (strict schema, IPs /
  user agents / cookies / user ids stripped, pattern-hash de-duplication,
  corroboration counting). Corroborated findings merge into the shared
  Threat Library in its daily update (`GET /v1/intel/status`). A
  single-site deployment works standalone — the network part is the
  filing/ingest protocol plus the merge logic.
- **Compliance & SIEM** — structured JSON audit log (`src/data/audit.jsonl`,
  rotated past 5 MB), a compliance report endpoint
  (`GET /api/compliance/report`, also on the dashboard), an audit export
  (`GET /api/audit/export`), and optional SIEM webhook forwarding
  (`SIEM_WEBHOOK_URL`, optional HMAC `SIEM_WEBHOOK_SECRET`).
- **Community rules marketplace** — detection rules live in `rules/` as
  JSON (`id`, `name`, `version`, `author`, `description`, `severity`,
  `match`, `risk` 0–30, `action` boost/flag). Rules are validated on load;
  invalid files are reported and not loaded. Three sample rules ship with
  the repo (see `rules/README.md`).
- **Durable state** — blocks, dossiers, reputation, baselines, and pending
  intel findings survive a server restart in a file-backed store
  (`src/data/state.json`, atomic tmp+rename writes). See "Production deploy"
  for the Render free-tier caveat.
- **Health & readiness** — `GET /healthz` (liveness) and `GET /readyz`
  (readiness: library loaded, AgentPulse feed state). Structured JSON
  logging throughout; request bodies capped at 64 KB, URLs at 2,048 chars,
  header count/size caps.

## Quick start

```bash
# One-line install (once this repo is public/clonable):
curl -fsSL https://raw.githubusercontent.com/Akshat-Srivastava-PS/Verigus/main/install.sh | bash

# …or from a checkout:
npm install && npm start
```

Then open:

- Demo shop: http://localhost:3000/
- Read-only dashboard: http://localhost:3000/dashboard
- Guard status (JSON): http://localhost:3000/api/status
- Agent contract: http://localhost:3000/agents.txt

## Try the simulated attacks

All simulator traffic is simulated; the guard logic deciding on it is real.

```bash
npm run simulate                 # good, suspicious, and malicious personas
npm run simulate:breaking-change # also fire a simulated AgentPulse breaking-change signal
npm test                         # unit tests: scoring, fast path, final blocks, production features
```

The simulator first fires benign warm-up traffic from several agents so
the guard completes observe mode on its own decision and switches to
enforcement — that is the observe-first behaviour, live. Then the personas:
a verified shopping agent (real Web Bot Auth fast path), a first-time
curious agent (allow, low risk), a bulk scraper that drifts outside its
declared purpose (challenge → sandbox → block), a credential prober
(block), a verified agent with a fake purpose (demoted to L1 mid-session),
an unaffiliated swarm (observed — a burst without sensitive targeting or
drift scores mid-low per node), a coordinated swarm under one operator
(observed at elevated risk — swarm boost), a prompt-injection attacker
(direct injection, then an indirect echo of poisoned content, then the
content is restored), a tool-chain attacker (read-then-send), and a
mandate agent (valid AP2 mandate places an order; expired mandate is
denied). Watch the dashboard feed and the blocked-agent dossiers as they
land.

Known limitation of this build: unaffiliated nodes are still judged on
their own record — a swarm with no shared operator reads as separate
mid-low-risk nodes. Correlation is operator-level: four or more nodes from
one operator running one task shape are boosted as a coordinated swarm.

## How the fast path is verified in this model

Real deployments verify Web Bot Auth (Ed25519, RFC 9421) signatures or
signed A2A agent cards against operator-published keys in
`src/data/operator-keys.json` (or the `VERIGUS_OPERATOR_KEYS` environment
variable, JSON of the same shape). A keyid that is an `https://` URL is
fetched (cached 1 h, 5 s timeout) and expected to be a PEM public key or
JSON `{ "publicKey": "<PEM or JWK>" }`. Signatures must be at most 15
minutes old. The check structure — identity + authentic purpose +
behaviour match, re-checked every request — is the real product rule.

The simulator signs with a **demo Ed25519 keypair** generated fresh at
first server start and stored in a gitignored local file
(`.demo-operator-keypair.json`); its public key is registered in-memory
under operator `demo-agent`. Honest limitation: a deployment generates its
own keypair at first boot, so attestations signed with the local demo
keypair cannot verify against the live Render deployment — the fast path
verifies for real on local runs, and the live deployment verifies any
operator whose key is in its registry.

## Onboarding a new site

```bash
npm run onboard -- --site myshop.example.com
```

Generates a site id + Ed25519 keypair, writes `verigus.site.json`
(public) and `verigus.site.key.json` (0600, private), and prints the
one-line install, a Render Blueprint snippet, and the dashboard URL.
Keep `verigus.site.key.json` private — it is the site's signing key.

## Deploying elsewhere

- **Edge worker** — `workers/verigus-edge.js` is a Cloudflare-Workers-style
  adapter that calls `POST /guard/decision` and applies the decision at
  the edge. Fail-open by default; set `FAIL_CLOSED=true` to fail closed.
- **Gateway plugin** — `src/gatewayPlugin.js` exports
  `createGuardMiddleware(guard)` for any Node HTTP framework; it renders
  allow/observe/challenge/throttle/sandbox/block exactly like the built-in
  server.
- **Guard decision API** — `POST /guard/decision` with
  `{ method, path, query, headers }` returns the guard's real decision for
  a request descriptor, without serving content.

## Production deploy

The guard runs on Render's free Web Service tier from `render.yaml`
(auto-deploy on push to main). The file-backed store keeps blocks,
reputation, and baselines across a **restart** — but Render's free-tier
filesystem is ephemeral, so a **redeploy resets state** (blocks, dossiers,
reputation, baseline) to a fresh start. That is the documented trade-off
of the free tier, not a bug.

The production step, when the site is ready to pay for it, is one of:

1. A Render **persistent disk** mounted at `src/data`, or
2. A `DATABASE_URL` Postgres adapter behind the same store interface
   (the store is the only component that touches persistence).

Either way the guard's interface does not change. Do not switch the live
deployment to a paid plan without the owner's say-so — the free tier stays.

## Project layout

```
src/
  server.js          Guard + demo shop + read-only dashboard API
  guard.js           The guardian: intercept, score, decide, act (no unblock exists)
  scoring.js         Data sensitivity first, velocity second (0–100 risk)
  taskGraph.js       Session task graphs: judge the task, not the request
  firstContact.js    Observe-first protocol + verified fast path + demotion
  webBotAuth.js      Real Web Bot Auth (Ed25519, RFC 9421) verification
  delegation.js      AP2 mandates, Visa TAP, signed A2A agent cards
  policies.js        Per-endpoint / per-transaction policies (+ data/policies.json)
  injection.js       Live prompt-injection + tool-chain detection
  integrity.js       Data-integrity watch (poisoning, exfiltration shapes)
  decoy.js           Interactive L4 sandbox (per-agent fake shop)
  reputation.js      Agent reputation registry (+ swarm correlation)
  intel.js           Cross-site threat-intel filing + merge
  rules.js           Community rules marketplace loader (+ rules/)
  agentContract.js   Published agent contract + sanctioned MCP door
  gatewayPlugin.js   Node middleware for gateway deploys
  store.js           Durable file-backed state (blocks, reputation, baseline)
  audit.js           Structured JSON logging + audit log + SIEM webhook
  threatLibrary.js   Daily-refreshing library (seeded from documented research)
  agentpulse.js      Live AgentPulse feed + breaking-change re-check trigger
  baseline.js        Observe-mode baseline, guard-decided readiness, live ETA
  dossier.js         Blocked-agent dossier builder (read-only)
  data/threat-library.json   Seeded library (top 10 + blueprint taxonomy)
  data/policies.json         Endpoint / transaction policy set
  data/operator-keys.json    Operator public-key registry (empty by default)
  public/dashboard.html      Read-only owner console (dark security console)
scripts/
  simulate.js        Scripted agent personas (good / suspicious / malicious)
  refresh-library.js Manual trigger for the daily library refresh
  onboard.js         Self-serve onboarding for a new site
workers/
  verigus-edge.js    Cloudflare-Workers-style edge adapter
rules/
  *.json             Community detection rules (+ rules/README.md format doc)
test/
  guard.test.js      Unit tests (scoring, fast path, final blocks)
  production.test.js Production tests (Web Bot Auth, mandates, policies,
                     reputation, intel, integrity, injection, rules, store)
install.sh           One-line install
render.yaml          Render Blueprint (free Web Service, auto-deploy)
```

## Honesty notes

- The demo shop, its products, and all simulator traffic are simulated.
  The guard's scoring, fast-path, ladder, dossier, library, and AgentPulse
  feed logic are real and runnable.
- The AgentPulse `/v1/metrics` endpoint was verified live on 2026-11-26.
  If the free-tier service sleeps or is unreachable, the feed logs it and
  the guard continues on its seeded library.
- The live Render deployment generates its own demo Ed25519 keypair at
  first boot, so locally-signed attestations cannot verify against it
  (see "How the fast path is verified"). The fast path verifies for real
  on local runs and for any registered operator key.
- No market-size, pricing, or funding figures are claimed anywhere here.
- The dashboard is read-only by design. If you believe a block is wrong,
  export the dossier for the record — the block itself still stands.

## Roadmap (from the blueprint)

- **Phase 1 · MVP** — done (v0.1): proxy deployment, observe-first,
  scoring v1, First-Contact Protocol, Task Graph v1, Threat Library v1 with
  AgentPulse integrated.
- **Phase 2 · V1** — done (v0.2.0): verified fast path with real Web Bot
  Auth / A2A card verification, delegated-authority verification
  (AP2 / Visa TAP), interactive sandbox mode, live response-side
  indirect-injection + tool-chain detection, published agent contract +
  MCP door, edge worker + gateway plugin, self-serve onboarding.
- **Phase 3 · Platform** — done (v0.2.0): cross-site threat-intelligence
  network feeding the Threat Library, agent reputation registry with
  purpose-mismatch history, per-endpoint policies, data-integrity watch,
  compliance reports + SIEM integrations, community rules marketplace.
