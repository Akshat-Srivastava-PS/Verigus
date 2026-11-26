// Entry point — the guard in front of a demo shop, plus the read-only
// owner dashboard. Zero dependencies; plain Node.js http.
//
//   npm start            -> guard + demo shop on http://localhost:3000
//   npm run simulate     -> fire scripted agent traffic at the demo shop
//   npm test             -> unit tests for scoring / fast path / final blocks
//
// The demo shop (shop.example.com in the blueprint) is fictional data for
// the working model. The guard logic deciding on its traffic is real.
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const { Guard } = require('./guard');
const { ThreatLibrary } = require('./threatLibrary');
const { AgentPulseFeed } = require('./agentpulse');

// --- Demo operator key -----------------------------------------------------
// Generated fresh at first start and kept in a gitignored local file.
// The simulator signs its "verified identity" attestations with it, which
// lets the guard exercise the real fast-path check structure (identity +
// purpose + behaviour). Production would verify Web Bot Auth Ed25519
// signatures against operator-published keys instead. This key is a demo
// fixture, not a credential for any real service.
const KEY_PATH = path.join(__dirname, '..', '.demo-operator-key');
let demoOperatorKey;
try {
  demoOperatorKey = fs.readFileSync(KEY_PATH, 'utf8').trim();
} catch (_) {
  demoOperatorKey = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(KEY_PATH, demoOperatorKey);
}

// --- Wire the guard --------------------------------------------------------
const agentPulse = new AgentPulseFeed();
const library = new ThreatLibrary(agentPulse);
const guard = new Guard({ library, agentPulse, demoOperatorKey });

// Daily Threat Library refresh, on schedule from day one.
setInterval(() => {
  library.dailyRefresh()
    .then((r) => console.log(`[library] daily refresh: ${r.added} new entries, version ${library.version}`))
    .catch((e) => console.log(`[library] daily refresh failed: ${e.message}`));
}, config.libraryRefreshMs);

// Initial AgentPulse poll (non-blocking; guard works without it).
agentPulse.poll()
  .then(() => console.log('[agentpulse] live feed connected'))
  .catch((e) => console.log(`[agentpulse] feed unavailable at start (${e.message}) — library continues on seeded data`));

// --- Demo shop data (fictional, for the working model) ----------------------
const PRODUCTS = [
  { id: 1, name: 'Trail Runner Shoes', price: 129.99 },
  { id: 2, name: 'Canvas Backpack', price: 79.5 },
  { id: 3, name: 'Insulated Bottle', price: 24.0 },
  { id: 4, name: 'Merino Hoodie', price: 89.0 },
  { id: 5, name: 'Running Shorts', price: 39.99 },
];

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(html) });
  res.end(html);
}

function serveFile(res, filePath) {
  try {
    sendHtml(res, 200, fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    sendJson(res, 404, { error: 'not found' });
  }
}

// Demo shop content handlers (only reached after the guard clears traffic).
function demoShop(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  if (p === '/' || p === '/products') {
    return sendJson(res, 200, { site: config.siteName, products: PRODUCTS });
  }
  if (p === '/search') {
    const q = url.searchParams.get('q') || '';
    return sendJson(res, 200, { results: PRODUCTS.filter((x) => x.name.toLowerCase().includes(q.toLowerCase())) });
  }
  if (p === '/pricing') {
    return sendJson(res, 200, { pricing: PRODUCTS.map((x) => ({ id: x.id, price: x.price })) });
  }
  if (p === '/account') {
    return sendJson(res, 200, { account: 'demo-account', orders: 2 });
  }
  if (p === '/account/reset') {
    return sendJson(res, 200, { reset: 'demo password-reset page (no real auth in the working model)' });
  }
  if (p === '/login') {
    return sendJson(res, 200, { login: 'demo login page (no real auth in the working model)' });
  }
  if (p === '/api/v1/products') {
    return sendJson(res, 200, { products: PRODUCTS });
  }
  if (p === '/api/v1/orders') {
    return sendJson(res, 200, { orders: [{ id: 'ord-1', status: 'shipped' }] });
  }
  return sendJson(res, 404, { error: 'not found on the demo shop' });
}

// --- Read-only API (the dashboard's data source) ---------------------------
// GET only. There is no endpoint that changes a verdict, unblocks an agent,
// or overrides the guard — by design.
function api(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  if (p === '/api/status') return sendJson(res, 200, guard.status());
  if (p === '/api/feed') return sendJson(res, 200, { incidents: guard.incidents.slice(0, 50) });
  if (p === '/api/agents') {
    return sendJson(res, 200, [...guard.profiles.values()].map((x) => ({
      fingerprint: x.fingerprint.slice(0, 40), operator: x.operator, purpose: x.purpose,
      requests: x.requests, fastPath: x.fastPathGranted, known: x.known,
    })));
  }
  if (p === '/api/library') return sendJson(res, 200, { ...library.summary(), entries: library.entries });
  if (p === '/api/report') return sendJson(res, 200, guard.learningReport());
  const m = p.match(/^\/api\/dossier\/([\w-]+)$/);
  if (m) {
    const dossier = [...guard.blocked.values()].find((d) => d.id === m[1]);
    if (!dossier) return sendJson(res, 404, { error: 'no such dossier' });
    return sendJson(res, 200, dossier);
  }
  return sendJson(res, 404, { error: 'unknown api route' });
}

// --- HTTP server: every request passes through the guard first --------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  req.path = url.pathname;

  // Dashboard + owner API are the owner's read-only surface (not shop traffic).
  // NOTE: only the exact owner routes are intercepted here. The demo shop's
  // own API (/api/v1/products, /api/v1/orders) is shop traffic and must go
  // through the guard — a blanket startsWith('/api/') would let agents
  // bypass the guard entirely by calling the shop API.
  if (req.path === '/dashboard') return serveFile(res, path.join(__dirname, 'public', 'dashboard.html'));
  if (/^\/(api\/(status|feed|agents|library|report)|api\/dossier\/[\w-]+)$/.test(req.path)) return api(req, res);

  // Demo trigger for the AgentPulse breaking-change re-check (localhost
  // demo only; it exercises the re-check path, it does not change verdicts).
  if (req.path === '/guard/demo/breaking-change' && req.method === 'POST') {
    const results = guard.recheckAgentsForDependency('api/v1');
    return sendJson(res, 200, { trigger: 'breaking-change (simulated AgentPulse signal)', rechecked: results });
  }

  // Everything else is shop traffic -> through the guard.
  const decision = guard.handle(req);
  res.setHeader('X-Guard-Decision', `${decision.rung} ${decision.action}`);
  res.setHeader('X-Guard-Risk', String(decision.risk));

  switch (decision.action) {
    case 'allow':
    case 'observe':
      return demoShop(req, res);
    case 'challenge':
      return sendJson(res, 429, {
        error: 'guard challenge',
        message: 'Prove you are legitimate: present a signed attestation (Web Bot Auth / signed agent card).',
        risk: decision.risk, reason: decision.reason,
      });
    case 'throttle':
      res.setHeader('Retry-After', '60');
      return sendJson(res, 429, { error: 'throttled by the guard', risk: decision.risk, reason: decision.reason });
    case 'sandbox':
      // Decoy data: the attacker gets fake endpoints and prices, never real ones.
      return sendJson(res, 200, {
        sandbox: true,
        products: [{ id: 0, name: 'Decoy Product', price: 0.0 }],
        note: 'You are in the guard sandbox. This data is decoy.',
      });
    case 'block':
      return sendJson(res, 403, {
        error: 'blocked by the guard',
        risk: decision.risk,
        reason: decision.reason,
        dossierId: decision.dossierId || null,
        note: 'This block is final and permanent. There is no unblock.',
      });
    default:
      return demoShop(req, res);
  }
});

server.listen(config.port, () => {
  console.log(`Verigus (working model) listening on http://localhost:${config.port}`);
  console.log(`  Demo shop:   http://localhost:${config.port}/`);
  console.log(`  Dashboard:   http://localhost:${config.port}/dashboard  (read-only)`);
  console.log(`  Guard mode:  OBSERVE — learning the site baseline before any enforcement.`);
  console.log(`  Try it:      npm run simulate`);
});
