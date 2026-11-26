// Delegated-authority verification (blueprint Phase 2).
//
// Before an agent may act on someone else's behalf — place an order, move
// money, change an account — the guard verifies the delegation itself:
//   * AP2-style mandates: a signed JSON mandate from the principal
//     (the human or service that delegated) naming the agent, the scope
//     (endpoints/actions), and an expiry. Signature is Ed25519 over the
//     canonical JSON of the mandate; the principal's public key comes from
//     the operator key registry.
//   * Visa TAP-style payment authorizations: a signed token naming the
//     merchant, amount, currency, and expiry.
//   * Signed A2A agent cards: a JSON agent card (name, url, capabilities,
//     publicKey) signed with the key in the card itself; the card is
//     verified against the registry when the operator is known.
//
// Mandates/cards arrive as base64url JSON in X-Agent-Mandate / X-Agent-Card.
// A failed check never grants authority — the guard denies the transaction
// and logs the attempt. Verification is synchronous except key fetching,
// which the registry handles (verifyWebBotAuth covers URL keyids).
'use strict';

const crypto = require('crypto');

/** Canonical JSON: sorted keys, recursive — the exact bytes that are signed. */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

function parsePublicKey(material) {
  if (typeof material === 'string') {
    const t = material.trim();
    if (t.startsWith('-----BEGIN')) return crypto.createPublicKey(t);
    return crypto.createPublicKey({ key: JSON.parse(t), format: 'jwk' });
  }
  return crypto.createPublicKey({ key: material, format: 'jwk' });
}

function verifyEd25519({ payload, signatureB64, publicKeyMaterial }) {
  if (!payload || !signatureB64 || !publicKeyMaterial) return { ok: false, reason: 'missing payload, signature, or key' };
  let publicKey;
  try { publicKey = parsePublicKey(publicKeyMaterial); } catch (e) {
    return { ok: false, reason: `public key unusable: ${e.message}` };
  }
  let sig;
  try { sig = Buffer.from(signatureB64, 'base64'); } catch (_) {
    return { ok: false, reason: 'signature is not valid base64' };
  }
  let ok = false;
  try { ok = crypto.verify(null, Buffer.from(payload), publicKey, sig); } catch (_) { ok = false; }
  return ok ? { ok: true } : { ok: false, reason: 'signature does not verify' };
}

function decodeB64Json(headerValue) {
  if (!headerValue) return { ok: false, reason: 'header absent' };
  try {
    const json = Buffer.from(headerValue, 'base64url').toString('utf8');
    return { ok: true, value: JSON.parse(json) };
  } catch (e) {
    return { ok: false, reason: `not valid base64url JSON: ${e.message}` };
  }
}

function checkExpiry(expiresAt) {
  if (!expiresAt) return { ok: false, reason: 'no expiry on the delegation' };
  const exp = Date.parse(expiresAt);
  if (Number.isNaN(exp)) return { ok: false, reason: 'expiry is not a valid date' };
  if (exp <= Date.now()) return { ok: false, reason: 'delegation expired' };
  return { ok: true };
}

/**
 * Verify an AP2-style mandate.
 * mandate: { type:"ap2-mandate", mandate_id, principal, agent, scope:[...],
 *   amount_limit?, currency?, expires_at, signature }
 * The signature covers the canonical JSON of the mandate WITHOUT the
 * signature field. The principal's key comes from the registry (by
 * principal id) or, when the mandate embeds one, from mandate.principal_public_key.
 */
function verifyMandate(mandate, registry) {
  if (!mandate || typeof mandate !== 'object') return { ok: false, reason: 'no mandate presented' };
  if (mandate.type && mandate.type !== 'ap2-mandate') return { ok: false, reason: `mandate type "${mandate.type}" is not an AP2 mandate` };
  for (const f of ['mandate_id', 'principal', 'agent', 'scope', 'expires_at', 'signature']) {
    if (mandate[f] === undefined || mandate[f] === null) return { ok: false, reason: `mandate is missing "${f}"` };
  }
  if (!Array.isArray(mandate.scope) || mandate.scope.length === 0) {
    return { ok: false, reason: 'mandate scope is empty' };
  }
  const exp = checkExpiry(mandate.expires_at);
  if (!exp.ok) return exp;
  let keyMaterial = mandate.principal_public_key || null;
  if (!keyMaterial && registry && registry.byOperator && registry.byOperator.has(mandate.principal)) {
    keyMaterial = registry.byOperator.get(mandate.principal).publicKey;
  }
  if (!keyMaterial) return { ok: false, reason: `no published key for principal "${mandate.principal}"` };
  const { signature, ...unsigned } = mandate;
  const sig = verifyEd25519({ payload: canonicalJson(unsigned), signatureB64: signature, publicKeyMaterial: keyMaterial });
  if (!sig.ok) return { ok: false, reason: `mandate signature invalid: ${sig.reason}` };
  return { ok: true, mandate, reason: 'mandate verified: principal, scope, and expiry all check out' };
}

/** Does the mandate's scope cover this transaction (endpoint + action)? */
function mandateCovers(mandate, { endpoint, action }) {
  if (!mandate || !Array.isArray(mandate.scope)) return false;
  return mandate.scope.some((s) => {
    if (typeof s === 'string') {
      // Scope entries are endpoint patterns, optionally with an action: "POST /api/v1/orders".
      const [methodPart, pathPart] = s.includes(' ') ? s.split(/\s+/, 2) : [null, s];
      const pathOk = new RegExp(`^${pathPart.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*')}$`).test(endpoint);
      const methodOk = !methodPart || !action || methodPart.toUpperCase() === String(action).toUpperCase();
      return pathOk && methodOk;
    }
    if (s && typeof s === 'object') {
      const pathOk = s.endpoint ? new RegExp(s.endpoint).test(endpoint) : true;
      const actionOk = s.action ? s.action.toUpperCase() === String(action || '').toUpperCase() : true;
      return pathOk && actionOk;
    }
    return false;
  });
}

/**
 * Verify a Visa TAP-style payment authorization token.
 * token: { type:"tap-payment-authorization", token_id, merchant, amount,
 *   currency, expires_at, signature } — signed by the merchant/principal
 * over the canonical JSON without the signature field.
 */
function verifyTapToken(token, registry) {
  if (!token || typeof token !== 'object') return { ok: false, reason: 'no payment authorization presented' };
  if (token.type && token.type !== 'tap-payment-authorization') {
    return { ok: false, reason: `token type "${token.type}" is not a TAP payment authorization` };
  }
  for (const f of ['token_id', 'merchant', 'amount', 'currency', 'expires_at', 'signature']) {
    if (token[f] === undefined || token[f] === null) return { ok: false, reason: `payment token is missing "${f}"` };
  }
  const exp = checkExpiry(token.expires_at);
  if (!exp.ok) return exp;
  let keyMaterial = token.merchant_public_key || null;
  if (!keyMaterial && registry && registry.byOperator && registry.byOperator.has(token.merchant)) {
    keyMaterial = registry.byOperator.get(token.merchant).publicKey;
  }
  if (!keyMaterial) return { ok: false, reason: `no published key for merchant "${token.merchant}"` };
  const { signature, ...unsigned } = token;
  const sig = verifyEd25519({ payload: canonicalJson(unsigned), signatureB64: signature, publicKeyMaterial: keyMaterial });
  if (!sig.ok) return { ok: false, reason: `payment token signature invalid: ${sig.reason}` };
  return { ok: true, token, reason: 'payment authorization verified' };
}

/**
 * Verify a signed A2A agent card.
 * card: { name, url, version, capabilities:[...], publicKey, signature }
 * The signature covers the canonical JSON of the card without the
 * signature field, made with the key inside the card. When the operator
 * is in the registry, the card key must ALSO match the registered key.
 */
function verifyAgentCard(card, registry) {
  if (!card || typeof card !== 'object') return { ok: false, reason: 'no agent card presented' };
  for (const f of ['name', 'url', 'publicKey', 'signature']) {
    if (!card[f]) return { ok: false, reason: `agent card is missing "${f}"` };
  }
  if (registry && registry.byOperator && card.name && registry.byOperator.has(card.name)) {
    const registered = registry.byOperator.get(card.name).publicKey;
    const cardKey = typeof card.publicKey === 'string' ? card.publicKey.trim() : JSON.stringify(card.publicKey);
    const regKey = typeof registered === 'string' ? registered.trim() : JSON.stringify(registered);
    if (registered && cardKey !== regKey) {
      return { ok: false, reason: 'agent card key does not match the registered key for this operator' };
    }
  }
  const { signature, ...unsigned } = card;
  const sig = verifyEd25519({ payload: canonicalJson(unsigned), signatureB64: signature, publicKeyMaterial: card.publicKey });
  if (!sig.ok) return { ok: false, reason: `agent card signature invalid: ${sig.reason}` };
  return { ok: true, card, reason: 'agent card verified' };
}

/** Sign a mandate/token/card payload (used by the simulator and tests). */
function signDelegation(payload, privateKeyPem) {
  const sig = crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKeyPem);
  return { ...payload, signature: sig.toString('base64') };
}

module.exports = {
  canonicalJson, decodeB64Json, verifyMandate, mandateCovers,
  verifyTapToken, verifyAgentCard, signDelegation,
};
