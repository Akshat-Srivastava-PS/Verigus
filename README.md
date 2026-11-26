# Verigus — AI Agent Protection Layer

> **Every agent verified, every threat remembered.**

An AI protection layer that sits in front of a website — before traffic ever
touches the origin — watching for other AI agents trying to probe, steal, or
break things, and reacting on its own. Not another crawler blocker: this one
is built for the agents nobody else can handle — the unsigned, undeclared
majority — and judges the whole task they're carrying out, not single
requests.

This repository is the **working model** (v0.1) of the product defined in
the product blueprint developed alongside it (blueprint, market research,
and stakeholder pitch deck in Akshat's Drive). It implements the
blueprint's core end to end, against a small demo shop included in the repo.

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
- **Response ladder** — L0 allow, L1 observe & score, L2 challenge, L3
  throttle, L4 sandbox (decoy data), L5 block & report. One narrow
  exception: a direct hit on a known sensitive path (`/.env`, `/.git`,
  `/config`) is refused instantly, even in observe mode.
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

## Quick start

```bash
# One-line install (once this repo is public/clonable):
curl -fsSL https://raw.githubusercontent.com/Akshat-Srivastava-PS/verigus/main/install.sh | bash

# …or from a checkout:
npm install && npm start
```

Then open:

- Demo shop: http://localhost:3000/
- Read-only dashboard: http://localhost:3000/dashboard
- Guard status (JSON): http://localhost:3000/api/status

## Try the simulated attacks

All simulator traffic is simulated; the guard logic deciding on it is real.

```bash
npm run simulate                 # good, suspicious, and malicious personas
npm run simulate:breaking-change # also fire a simulated AgentPulse breaking-change signal
npm test                         # unit tests: scoring, fast path, final blocks
```

The simulator first fires benign warm-up traffic from several agents so
the guard completes observe mode on its own decision and switches to
enforcement — that is the observe-first behaviour, live. Then the personas:
a verified shopping agent (fast path), a first-time curious agent (allow,
low risk), a bulk scraper that drifts outside its declared purpose
(challenge → sandbox → block), a credential prober (block), a
verified agent with a fake purpose (demoted to L1 mid-session), and an
agent swarm (observed — a burst without sensitive targeting or drift
scores mid-low per node). Watch the dashboard feed and the blocked-agent
dossiers as they land.

Known limitation of this working model: the guard scores each agent on
its own record. Cross-node correlation — six agents, one operator, one
task — is not scored yet, so a coordinated swarm reads as six separate
mid-low-risk nodes rather than one coordinated attack. The dossier,
scoring, and ladder are per-agent; swarm correlation is on the roadmap.

## How the fast path is verified in this model

Real deployments verify Web Bot Auth (Ed25519) signatures or signed A2A
agent cards against operator-published keys. This working model simulates
that attestation with an HMAC over (operator, purpose, timestamp) using a
demo operator key generated fresh at first start and stored in a gitignored
local file (`.demo-operator-key`). The check structure — identity +
authentic purpose + behaviour match, re-checked every request — is the real
product rule; only the signature scheme is a demo stand-in.

## Project layout

```
src/
  server.js          Guard + demo shop + read-only dashboard API
  guard.js           The guardian: intercept, score, decide, act (no unblock exists)
  scoring.js         Data sensitivity first, velocity second (0–100 risk)
  taskGraph.js       Session task graphs: judge the task, not the request
  firstContact.js    Observe-first protocol + verified fast path + demotion
  threatLibrary.js   Daily-refreshing library (seeded from documented research)
  agentpulse.js      Live AgentPulse feed + breaking-change re-check trigger
  baseline.js        Observe-mode baseline, guard-decided readiness, live ETA
  dossier.js         Blocked-agent dossier builder (read-only)
  data/threat-library.json   Seeded library (top 10 + blueprint taxonomy)
  public/dashboard.html      Read-only owner console
scripts/
  simulate.js        Scripted agent personas (good / suspicious / malicious)
  refresh-library.js Manual trigger for the daily library refresh
test/
  guard.test.js      Unit tests
install.sh           One-line install
```

## Honesty notes

- The demo shop, its products, and all simulator traffic are simulated.
  The guard's scoring, fast-path, ladder, dossier, library, and AgentPulse
  feed logic are real and runnable.
- The AgentPulse `/v1/metrics` endpoint was verified live on 2026-11-26.
  If the free-tier service sleeps or is unreachable, the feed logs it and
  the guard continues on its seeded library.
- No market-size, pricing, or funding figures are claimed anywhere here.
- The dashboard is read-only by design. If you believe a block is wrong,
  export the dossier for the record — the block itself still stands.

## Roadmap (from the blueprint)

- **Phase 1 · MVP** — this working model: proxy deployment, observe-first,
  scoring v1, First-Contact Protocol, Task Graph v1, Threat Library v1 with
  AgentPulse integrated.
- **Phase 2 · V1** — verified fast path with real Web Bot Auth / A2A card
  verification, delegated-authority verification (AP2 / Visa TAP), sandbox
  mode, response-side indirect-injection scanning, published agent contract.
- **Phase 3 · Platform** — cross-site threat-intelligence network, agent
  reputation registry, per-endpoint policies, data-integrity watch.
