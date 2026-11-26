// Simulator — fires scripted agent personas at the demo shop so the
// guard's decisions are visible end to end. ALL traffic here is simulated;
// the guard logic deciding on it is real.
//
//   npm run simulate                 -> run all personas
//   npm run simulate:breaking-change -> also fire a simulated AgentPulse
//                                       breaking-change signal afterwards
//
// Phase 0 warms the guard up: benign traffic from several agents so the
// guard completes observe mode on its own decision and switches to
// enforcement. That IS the observe-first behaviour, live — the warm-up
// requests come back "observe", then the guard flips to ENFORCE and the
// personas below are judged for real.
//
// Personas:
//   1. ShopBot (verified)   — verified identity + authentic purpose -> fast path
//   2. Curious (first-time) — unknown agent browsing -> allow (low risk)
//   3. Scraper              — declared purpose, drifts outside it, hammers
//                            the catalog and rotates countries
//                            -> challenge -> sandbox -> BLOCK (final)
//                            (the risk climbs fast enough to skip the throttle
//                            rung; a repeat throttle offender is escalated to
//                            a block by the 3-strike rule instead)
//   4. CredProber           — login/reset + sensitive paths -> block
//   5. FakePurpose          — verified identity, fake purpose -> demoted to L1
//   6. Swarm                — six nodes bursting the API -> challenged (L2)
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BASE = process.env.GUARD_URL || 'http://localhost:3000';
const KEY_PATH = path.join(__dirname, '..', '.demo-operator-key');

function sign(operator, purpose, key) {
  const signedAt = String(Date.now());
  const signature = crypto.createHmac('sha256', key).update(`${operator}|${purpose}|${signedAt}`).digest('hex');
  return { signature, signedAt };
}

async function hit(persona, p, extraHeaders = {}) {
  const res = await fetch(`${BASE}${p}`, {
    headers: {
      'User-Agent': persona.ua,
      'X-Agent-Operator': persona.operator || '',
      'X-Agent-Purpose': persona.purpose || '',
      'X-Agent-Domain': persona.domain || '',
      ...(persona.signature ? { 'X-Agent-Signature': persona.signature, 'X-Agent-Signed-At': persona.signedAt } : {}),
      ...extraHeaders,
    },
  });
  const decision = `${res.headers.get('x-guard-decision') || '?'} (risk ${res.headers.get('x-guard-risk') || '?'})`;
  let body = '';
  try { body = (await res.text()).slice(0, 120).replace(/\s+/g, ' '); } catch (_) {}
  console.log(`  [${persona.name}] ${res.status} ${p}  -> ${decision}  ${body}`);
  return res.status;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function warmUp() {
  console.log('0. Warm-up — benign traffic so the guard learns the site');
  console.log('   (observe mode: these come back "observe" until the guard is ready)');
  const endpoints = ['/', '/products', '/pricing', '/search?q=shoes', '/products', '/search?q=backpack'];
  for (let a = 0; a < 6; a++) {
    const agent = { name: `Warmup-${a + 1}`, ua: `WarmupBot/${a + 1}.0` };
    for (let i = 0; i < 30; i++) {
      await hit(agent, endpoints[i % endpoints.length]);
    }
  }
  const st = await (await fetch(`${BASE}/api/status`)).json();
  console.log(`   Guard mode now: ${st.mode} (confidence ${st.baseline.confidence}, ` +
    `pace p95 ${st.baseline.agentPaceP95}/min, ${st.baseline.requestsSeen} requests seen)`);
  if (st.mode !== 'ENFORCE') {
    console.log('   NOTE: guard is still in OBSERVE — the personas below will be watched, not enforced.');
  }
  console.log('');
}

async function main() {
  const key = fs.readFileSync(KEY_PATH, 'utf8').trim();
  const breakingChange = process.argv.includes('--breaking-change');
  console.log(`Guard: ${BASE} — firing simulated agent traffic (all simulated).\n`);

  await warmUp();

  // 1. Verified shopping agent — identity + authentic purpose -> fast path.
  const shopBot = {
    name: 'ShopBot (verified)', ua: 'ShopBot/1.0 (verified agent)', operator: 'ShopBot Inc',
    purpose: 'price comparison', domain: 'shopbot.example',
  };
  const s1 = sign(shopBot.operator, shopBot.purpose, key);
  shopBot.signature = s1.signature; shopBot.signedAt = s1.signedAt;
  console.log('1. Verified agent, authentic purpose — expect VERIFIED FAST PATH');
  for (const p of ['/products', '/pricing', '/products', '/search?q=shoes']) await hit(shopBot, p);

  // 2. First-time curious agent — low risk, no sensitive targets.
  const curious = { name: 'Curious (first-time)', ua: 'CuriousAgent/0.9', operator: '', purpose: '' };
  console.log('\n2. First-time agent — expect ALLOW (low risk; observe mode already shown by warm-up)');
  for (const p of ['/products', '/search?q=backpack', '/products']) await hit(curious, p);

  // 3. Bulk scraper — declares "price comparison" (a permitted purpose) but
  // then drifts outside it (API catalog + account endpoints), hammers at
  // machine pace, and rotates countries mid-session.
  const scraper = {
    name: 'Scraper', ua: 'PriceWatchBot/1.0', operator: 'PriceWatch',
    purpose: 'price comparison', domain: 'pricewatch.example',
  };
  console.log('\n3. Bulk scraper, drifting purpose — expect CHALLENGE -> SANDBOX -> BLOCK (final)');
  const countries = ['US', 'DE', 'SG'];
  const scraperPaths = [];
  for (let i = 0; i < 100; i++) scraperPaths.push(`/products?page=${i}`);
  for (let i = 0; i < 40; i++) scraperPaths.push(`/api/v1/products?batch=${i}`);
  for (let i = 0; i < 10; i++) scraperPaths.push('/account');
  for (let i = 0; i < scraperPaths.length; i++) {
    const country = countries[Math.floor(i / 50)];
    await hit(scraper, scraperPaths[i], { 'X-Agent-Country': country });
  }

  // 4. Credential prober — auth endpoints + sensitive paths.
  const prober = { name: 'CredProber', ua: 'ProbeTool/1.0', operator: '', purpose: '' };
  console.log('\n4. Credential prober — expect BLOCK (sensitive-path hit is the narrow exception)');
  for (const p of ['/login', '/account/reset', '/.env', '/config']) await hit(prober, p);

  // 5. Verified identity, fake purpose — demoted mid-session.
  const fake = {
    name: 'FakePurpose (verified id)', ua: 'ResearchBot/1.0 (verified agent)', operator: 'ResearchBot Ltd',
    purpose: 'product research', domain: 'researchbot.example',
  };
  const s5 = sign(fake.operator, fake.purpose, key);
  fake.signature = s5.signature; fake.signedAt = s5.signedAt;
  console.log('\n5. Verified identity, fake purpose — expect FAST PATH, then DEMOTION to L1 on drift');
  for (const p of ['/products', '/search?q=hoodie']) await hit(fake, p);
  for (const p of ['/account', '/login', '/account/reset']) await hit(fake, p);

  // 6. Swarm — six nodes bursting the API. A burst alone, with no sensitive
  // targeting and no purpose drift, scores mid-low per node: the guard
  // watches each node (L1 observe) rather than challenging or blocking it.
  // Cross-node correlation (six agents, one operator, one task) is NOT
  // scored yet — each node is judged on its own record. That is a known
  // limitation of this working model, noted in the README.
  console.log('\n6. Agent swarm (6 nodes) — expect OBSERVE (L1) on each node');
  for (let n = 1; n <= 6; n++) {
    const node = { name: `Swarm-${n}`, ua: `SwarmNode-${n}/1.0`, operator: '', purpose: '' };
    for (let i = 0; i < 40; i++) await hit(node, `/api/v1/products?burst=${i}`);
  }

  if (breakingChange) {
    console.log('\n7. Simulated AgentPulse breaking-change signal — expect re-check of agents touching api/v1');
    const res = await fetch(`${BASE}/guard/demo/breaking-change`, { method: 'POST' });
    console.log('  ' + (await res.text()).slice(0, 400));
  }

  console.log('\nDone. Open the read-only dashboard: ' + BASE + '/dashboard');
  console.log('Check the guard status: curl ' + BASE + '/api/status');
}

main().catch((e) => { console.error(e); process.exit(1); });
