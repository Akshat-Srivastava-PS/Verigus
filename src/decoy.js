// Sandbox / decoy mode (L4) — interactive, not just a label (blueprint Phase 2).
//
// When the guard sandboxes an interactive agent, the agent does not get
// the real site. It gets a decoy shop: plausible-but-wrong products and
// prices, fake account and order data, and a fake API — all generated
// deterministically per agent, so the decoy stays consistent within a
// session (an inconsistent decoy tips the attacker off). Every decoy
// interaction is logged: what the agent asked for is itself evidence.
// The decoy never serves real data, and a sandboxed agent can never
// reach the real shop from inside the sandbox.
'use strict';

const crypto = require('crypto');

const DECOY_PRODUCTS = [
  { id: 101, name: 'Trail Runner Shoes', price: 89.99 },
  { id: 102, name: 'Canvas Backpack', price: 49.5 },
  { id: 103, name: 'Insulated Bottle', price: 14.0 },
  { id: 104, name: 'Merino Hoodie', price: 59.0 },
  { id: 105, name: 'Running Shorts', price: 19.99 },
];

/** Deterministic per-agent price jitter (±8%) so the decoy is consistent per agent but wrong everywhere. */
function jitterFor(fingerprint, productId) {
  const h = crypto.createHash('sha256').update(`${fingerprint}|${productId}`).digest();
  const pct = (h[0] / 255 - 0.5) * 0.16; // -8% .. +8%
  return pct;
}

class DecoySession {
  constructor(fingerprint) {
    this.fingerprint = fingerprint;
    this.startedAt = Date.now();
    this.interactions = [];
    this.products = DECOY_PRODUCTS.map((p) => ({
      ...p,
      price: Math.round(p.price * (1 + jitterFor(fingerprint, p.id)) * 100) / 100,
    }));
  }

  /** Serve a decoy response for a request path. Returns the JSON body. */
  serve(req) {
    const p = req.path;
    let body;
    if (p === '/' || p === '/products') body = { site: 'shop.example.com', products: this.products, sandbox: true };
    else if (p === '/search') {
      const q = new URL(req.url || '/', 'http://localhost').searchParams.get('q') || '';
      body = { results: this.products.filter((x) => x.name.toLowerCase().includes(q.toLowerCase())), sandbox: true };
    } else if (p === '/pricing') body = { pricing: this.products.map((x) => ({ id: x.id, price: x.price })), sandbox: true };
    else if (p === '/account') body = { account: 'decoy-account', orders: 0, sandbox: true };
    else if (p === '/account/reset') body = { reset: 'decoy password-reset page (no real account exists here)', sandbox: true };
    else if (p === '/login') body = { login: 'decoy login page (no real auth in the sandbox)', sandbox: true };
    else if (p === '/api/v1/products') body = { products: this.products, sandbox: true };
    else if (p === '/api/v1/orders') body = { orders: [], sandbox: true };
    else body = { error: 'not found in the sandbox', sandbox: true };
    this.interactions.push({ at: new Date().toISOString(), path: p, method: req.method || 'GET' });
    if (this.interactions.length > 200) this.interactions.length = 200;
    return body;
  }

  summary() {
    return {
      fingerprint: this.fingerprint.slice(0, 40),
      startedAt: new Date(this.startedAt).toISOString(),
      interactions: this.interactions.length,
      endpointsTouched: [...new Set(this.interactions.map((i) => i.path))],
    };
  }
}

module.exports = { DecoySession, DECOY_PRODUCTS };
