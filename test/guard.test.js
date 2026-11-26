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

test('fast path requires identity AND authentic purpose AND behaviour match', () => {
  const key = 'test-demo-key';
  const crypto = require('crypto');
  const sign = (op, purpose) => {
    const signedAt = String(Date.now());
    return {
      signature: crypto.createHmac('sha256', key).update(`${op}|${purpose}|${signedAt}`).digest('hex'),
      signedAt,
    };
  };
  const agent = { operator: 'ShopBot Inc', purpose: 'price comparison', ...sign('ShopBot Inc', 'price comparison') };
  const session = fakeSession(['/products', '/pricing']);
  const ok = firstContact.evaluateFastPath(agent, session, key);
  assert.equal(ok.granted, true, 'verified identity + authentic purpose + matching behaviour grants the fast path');

  // Same agent, behaviour drifts to account endpoints -> denied.
  const drifted = fakeSession(['/products', '/account', '/login']);
  const denied = firstContact.evaluateFastPath(agent, drifted, key);
  assert.equal(denied.granted, false, 'behaviour outside the purpose shape denies the fast path');

  // Identity alone is never enough: unsigned agent.
  const unsigned = { operator: null, purpose: 'price comparison', signature: null, signedAt: null };
  assert.equal(firstContact.evaluateFastPath(unsigned, session, key).granted, false);
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

test('three throttles escalate to a final block', () => {
  // A repeat offender that keeps coming back at throttle level is escalated
  // to a permanent block on the third strike — the block risk is the
  // decision risk (score + library boost), and the block is final.
  // The guard gets a scratch blocks file so a block saved by one test run
  // cannot make the next run's agent already-blocked from request one.
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const scratchBlocks = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'verigus-test-')), 'blocks.json');
  const lib = new ThreatLibrary(null);
  const guard = new Guard({ library: lib, agentPulse: null, demoOperatorKey: 'test-key', blocksPath: scratchBlocks });
  guard.baseline.ready = true;
  guard.baseline.frozenPaceP95 = 58;
  const headers = {
    'user-agent': 'PriceWatchBot/1.0',
    'x-agent-operator': 'PriceWatch',
    'x-agent-purpose': 'price comparison',
    'x-agent-domain': '',
    'x-agent-country': 'US',
  };
  const mkReq = () => ({ path: '/api/v1/products', method: 'GET', headers, socket: { remoteAddress: '127.0.0.1' } });
  const seen = [];
  for (let i = 0; i < 40; i++) {
    const d = guard.handle(mkReq());
    seen.push(d.action);
    if (d.action === 'block') break;
  }
  assert.ok(seen.filter((a) => a === 'throttle').length >= 2, 'agent is throttled before the block');
  assert.equal(seen[seen.length - 1], 'block', 'third strike escalates to a block');
  const again = guard.handle(mkReq());
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
