// Unit tests for the guard's core rules. Run: npm test
// (Node's built-in test runner; zero dependencies.)
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const scoring = require('../src/scoring');
const firstContact = require('../src/firstContact');
const { Session } = require('../src/taskGraph');
const { Guard } = require('../src/guard');
const { ThreatLibrary } = require('../src/threatLibrary');

function fakeSession(paths) {
  const s = new Session('test-fp');
  for (const p of paths) s.add({ path: p, method: 'GET', dataClass: 'x' });
  return s;
}

test('scoring weights data sensitivity first: sensitive paths outrank velocity', () => {
  const profile = { purpose: null, identityRotations: 0, uaSpoofSuspected: false, countryHops: 0 };
  const sensitive = scoring.scoreSession(profile, fakeSession(['/.env', '/config']), 22);
  const fastPublic = scoring.scoreSession(profile, fakeSession(['/products', '/search', '/products']), 22);
  assert.ok(sensitive.total > fastPublic.total, 'sensitive-path session must score higher than fast public browsing');
  assert.equal(sensitive.breakdown.dataSensitivity, 40);
});

test('ladder maps risk to rungs (L0 allow … L5 block)', () => {
  assert.equal(scoring.ladderFor(10).rung, 'L0');
  assert.equal(scoring.ladderFor(30).rung, 'L1');
  assert.equal(scoring.ladderFor(50).rung, 'L2');
  assert.equal(scoring.ladderFor(70).rung, 'L3');
  assert.equal(scoring.ladderFor(80).rung, 'L4');
  assert.equal(scoring.ladderFor(95).rung, 'L5');
});

test('fast path requires identity AND authentic purpose AND behaviour match', async () => {
  const webBotAuth = require('../src/webBotAuth');
  const keypair = webBotAuth.generateKeypair();
  const registry = { byKeyid: new Map(), byOperator: new Map() };
  const rec = { operator: 'ShopBot Inc', keyid: 'shopbot-key-1', publicKey: keypair.publicKeyPem, domain: 'shopbot.example' };
  registry.byKeyid.set('shopbot-key-1', rec);
  registry.byOperator.set('ShopBot Inc', rec);
  // Each request is signed separately: @path and @query are covered components.
  const makeAgent = (purpose, requestPath) => {
    const [pathOnly, queryRaw] = requestPath.split('?');
    const signed = webBotAuth.signRequest({
      method: 'GET', authority: 'localhost:3000', path: pathOnly, query: queryRaw ? `?${queryRaw}` : '',
      agent: 'ShopBot Inc', privateKeyPem: keypair.privateKeyPem, keyid: 'shopbot-key-1',
    });
    return {
      operator: 'ShopBot Inc', purpose, method: 'GET', url: requestPath,
      headers: {
        host: 'localhost:3000',
        'signature-agent': signed.signatureAgent,
        'signature-input': signed.signatureInput,
        signature: signed.signature,
      },
    };
  };
  const session = fakeSession(['/products', '/pricing']);
  const ok = await firstContact.evaluateFastPath(makeAgent('price comparison', '/pricing'), session, registry);
  assert.equal(ok.granted, true, 'verified identity + authentic purpose + matching behaviour grants the fast path');
  assert.equal(ok.checks.identity.method, 'web-bot-auth');

  // Same agent, behaviour drifts to account endpoints -> denied.
  const drifted = fakeSession(['/products', '/account', '/login']);
  const denied = await firstContact.evaluateFastPath(makeAgent('price comparison', '/login'), drifted, registry);
  assert.equal(denied.granted, false, 'behaviour outside the purpose shape denies the fast path');

  // Identity alone is never enough: unsigned agent.
  const unsigned = { operator: null, purpose: 'price comparison', method: 'GET', url: '/pricing', headers: { host: 'localhost:3000' } };
  assert.equal((await firstContact.evaluateFastPath(unsigned, session, registry)).granted, false);

  // A tampered signature fails verification.
  const tampered = makeAgent('price comparison', '/pricing');
  tampered.headers.signature = tampered.headers.signature.replace(/.$/, 'A');
  assert.equal((await firstContact.evaluateFastPath(tampered, session, registry)).granted, false, 'tampered signature must not grant the fast path');
});

test('a block is final: no unblock method exists and blocked stays blocked', () => {
  assert.equal(typeof Guard.prototype.unblock, 'undefined');
  assert.equal(typeof Guard.prototype.allowlist, 'undefined');
  assert.equal(typeof Guard.prototype.override, 'undefined');
});

test('threat library seeds with the research top 10', () => {
  const lib = new ThreatLibrary(null);
  const ids = lib.entries.map((e) => e.id);
  for (const must of ['indirect-prompt-injection', 'tool-poisoning', 'exfiltration-benign-channels',
    'spoofed-stealth-identity', 'unsafe-tool-chaining', 'admin-internal-ssrf-probing',
    'rug-pull-change', 'credential-harvesting', 'loop-fanout-token-burning', 'scope-drift-rogue-agent']) {
    assert.ok(ids.includes(must), `library must seed ${must}`);
  }
  assert.ok(lib.entries.length >= 10);
});

test('three throttles escalate to a final block', async () => {
  // A repeat offender that keeps coming back at throttle level is escalated
  // to a permanent block on the third strike — the block risk is the
  // decision risk (score + library boost), and the block is final.
  // The guard gets scratch state + audit files so a block saved by one
  // test run cannot make the next run's agent already-blocked from request one.
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { Store } = require('../src/store');
  const { AuditLog } = require('../src/audit');
  const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verigus-test-'));
  const store = new Store(path.join(scratchDir, 'state.json'));
  const audit = new AuditLog(path.join(scratchDir, 'audit.jsonl'));
  const lib = new ThreatLibrary(null);
  const registry = { byKeyid: new Map(), byOperator: new Map() };
  const guard = new Guard({ library: lib, agentPulse: null, registry, store, audit });
  guard.baseline.ready = true;
  guard.baseline.frozenPaceP95 = 58;
  const headers = {
    'user-agent': 'PriceWatchBot/1.0',
    'x-agent-operator': 'PriceWatch',
    'x-agent-purpose': 'price comparison',
    'x-agent-domain': '',
    'x-agent-country': 'US',
  };
  const mkReq = () => ({ path: '/api/v1/products', method: 'GET', url: '/api/v1/products', headers, socket: { remoteAddress: '127.0.0.1' } });
  const seen = [];
  for (let i = 0; i < 40; i++) {
    const d = await guard.handle(mkReq());
    seen.push(d.action);
    if (d.action === 'block') break;
  }
  assert.ok(seen.filter((a) => a === 'throttle').length >= 2, 'agent is throttled before the block');
  assert.equal(seen[seen.length - 1], 'block', 'third strike escalates to a block');
  const again = await guard.handle(mkReq());
  assert.equal(again.action, 'block', 'block is final on the next request too');
  assert.ok(again.dossierId, 'blocked response carries the dossier id');
  const dossier = [...guard.blocked.values()].find((d) => d.id === again.dossierId);
  assert.ok(dossier, 'dossier exists for the blocked agent');
  assert.equal(dossier.risk, again.risk, 'dossier records the risk that triggered the block');
  assert.equal(typeof dossier.libraryBoost, 'number');
});

test('task graph classifies a sensitive-hunting session', () => {
  const s = fakeSession(['/products', '/.env', '/config']);
  assert.equal(s.taskShape(), 'sensitive-hunting');
});
