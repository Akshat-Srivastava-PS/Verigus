// Web Bot Auth verification — real Ed25519 HTTP Message Signatures
// (RFC 9421), replacing the demo HMAC attestation stand-in from v0.1.
//
// An agent proves its identity by sending:
//   Signature-Agent: <operator identifier, e.g. a domain or agent name>
//   Signature-Input: sig1=("@method" "@authority" "@path" "@query" "signature-agent");created=...;expires=...;keyid="...";tag="web-bot-auth"
//   Signature: sig1=:<base64 Ed25519 signature over the RFC 9421 base>:
//
// The signature base is one `"component": value` line per covered
// component, plus a final `"@signature-params"` line reproducing the
// parameters exactly as sent. Covered components supported here:
// @method, @authority, @path, @query, @scheme, @target-uri, signature-agent,
// and any named header (lower-cased). Unknown @-components fail closed.
//
// Keys resolve through the operator key registry (src/data/operator-keys.json
// plus VERIGUS_OPERATOR_KEYS env, JSON of the same shape). A keyid that is
// an https:// URL is fetched (cached 1h, 5 s timeout) — the document is
// expected to be a PEM public key, or JSON { "publicKey": "<PEM or JWK>" }.
//
// A demo Ed25519 keypair is generated at first start for the simulator
// (see server.js); its public key is registered in-memory under operator
// "demo-agent". That keypair is a demo fixture, not a credential.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REGISTRY_PATH = path.join(__dirname, 'data', 'operator-keys.json');
const MAX_ATTESTATION_AGE_S = 15 * 60; // signature must be at most 15 min old
const MAX_CLOCK_SKEW_S = 5 * 60;

function parsePublicKey(material) {
  if (typeof material === 'string') {
    const trimmed = material.trim();
    if (trimmed.startsWith('-----BEGIN')) return crypto.createPublicKey(trimmed);
    return crypto.createPublicKey({ key: JSON.parse(trimmed), format: 'jwk' });
  }
  return crypto.createPublicKey({ key: material, format: 'jwk' });
}

function loadRegistry() {
  const registry = { byKeyid: new Map(), byOperator: new Map() };
  const add = (operator, entry) => {
    if (!entry || typeof entry !== 'object') return;
    const rec = { operator, keyid: entry.keyid || null, publicKey: entry.publicKey || null, domain: entry.domain || null };
    if (rec.keyid) registry.byKeyid.set(rec.keyid, rec);
    if (operator) registry.byOperator.set(operator, rec);
  };
  try {
    const raw = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
    const operators = raw.operators || {};
    for (const [operator, entry] of Object.entries(operators)) add(operator, entry);
  } catch (_) { /* no registry file yet — env keys and the demo keypair still work */ }
  try {
    if (process.env.VERIGUS_OPERATOR_KEYS) {
      const raw = JSON.parse(process.env.VERIGUS_OPERATOR_KEYS);
      const operators = raw.operators || raw;
      for (const [operator, entry] of Object.entries(operators)) add(operator, entry);
    }
  } catch (_) { /* malformed env keys are ignored, not fatal */ }
  return registry;
}

/** Parse a Signature-Input header value. Returns { label, components, rawParams, params } or null. */
function parseSignatureInput(value) {
  if (!value || typeof value !== 'string') return null;
  const m = value.match(/^\s*([A-Za-z0-9_-]+)\s*=\s*\(([^)]*)\)\s*(;.*)?$/);
  if (!m) return null;
  const components = [...m[2].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  if (components.length === 0) return null;
  const rawParams = (m[3] || '').trim();
  const params = {};
  for (const part of rawParams.split(';')) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf('=');
    if (eq === -1) { params[t] = true; continue; }
    const k = t.slice(0, eq).trim();
    let v = t.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    else if (/^\d+$/.test(v)) v = Number(v);
    params[k] = v;
  }
  return { label: m[1], components, rawParams, params };
}

/** Parse a Signature header value. Returns Map<label, base64> or null. */
function parseSignature(value) {
  if (!value || typeof value !== 'string') return null;
  const out = new Map();
  for (const m of value.matchAll(/([A-Za-z0-9_-]+)\s*=\s*:([A-Za-z0-9+/=]+):/g)) {
    out.set(m[1], m[2]);
  }
  return out.size ? out : null;
}

function splitUrl(rawUrl) {
  const u = new URL(rawUrl, 'http://localhost');
  return { path: u.pathname, query: u.search || '' };
}

function componentValue(name, req) {
  const n = name.toLowerCase();
  const { path, query } = splitUrl(req.url || '/');
  if (n === '@method') return (req.method || 'GET').toUpperCase();
  if (n === '@authority') return String(req.headers['host'] || '').toLowerCase();
  if (n === '@path') return path;
  if (n === '@query') return query;
  if (n === '@scheme') return String(req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim().toLowerCase();
  if (n === '@target-uri') {
    const scheme = componentValue('@scheme', req);
    return `${scheme}://${componentValue('@authority', req)}${path}${query}`;
  }
  if (n === 'signature-agent') return String(req.headers['signature-agent'] || '');
  if (n.startsWith('@')) throw new Error(`unsupported component "${name}"`);
  // Named header, lower-cased. A missing header fails closed (RFC 9421).
  const v = req.headers[n];
  if (v === undefined) throw new Error(`covered header "${name}" is absent`);
  return Array.isArray(v) ? v.join(', ') : String(v);
}

/** Build the RFC 9421 signature base for the covered components. */
function buildSignatureBase(req, parsed) {
  const lines = parsed.components.map((c) => `"${c.toLowerCase()}": ${componentValue(c, req)}`);
  const paramsLine = `"@signature-params": (${parsed.components.map((c) => `"${c}"`).join(' ')})${parsed.rawParams ? parsed.rawParams : ''}`;
  lines.push(paramsLine);
  return lines.join('\n');
}

const _keyCache = new Map(); // url -> { publicKey, fetchedAt }

async function fetchKeyMaterial(url) {
  const cached = _keyCache.get(url);
  if (cached && Date.now() - cached.fetchedAt < 60 * 60 * 1000) return cached.publicKey;
  const body = await new Promise((resolve, reject) => {
    const lib = url.startsWith('https://') ? require('https') : require('http');
    const r = lib.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
        else reject(new Error(`key URL HTTP ${res.statusCode}`));
      });
    });
    r.on('timeout', () => r.destroy(new Error('key URL timed out')));
    r.on('error', reject);
  });
  let publicKey = body.trim();
  try {
    const parsed = JSON.parse(body);
    if (parsed && parsed.publicKey) publicKey = parsed.publicKey;
  } catch (_) { /* body is PEM text */ }
  _keyCache.set(url, { publicKey, fetchedAt: Date.now() });
  return publicKey;
}

/**
 * Verify a Web Bot Auth attestation on a request.
 * req: { method, url, headers } — headers lower-cased keys.
 * registry: from loadRegistry() (or a test registry { byKeyid, byOperator }).
 * Returns { ok, operator, keyid, reason }.
 */
async function verifyWebBotAuth(req, registry) {
  const agent = req.headers['signature-agent'] || null;
  const inputRaw = req.headers['signature-input'] || null;
  const sigRaw = req.headers['signature'] || null;
  if (!agent || !inputRaw || !sigRaw) {
    return { ok: false, operator: agent, keyid: null, reason: 'no Web Bot Auth attestation presented' };
  }
  const parsed = parseSignatureInput(inputRaw);
  if (!parsed) return { ok: false, operator: agent, keyid: null, reason: 'malformed Signature-Input header' };
  if (parsed.params.tag && parsed.params.tag !== 'web-bot-auth') {
    return { ok: false, operator: agent, keyid: null, reason: `signature tag "${parsed.params.tag}" is not web-bot-auth` };
  }
  const sigs = parseSignature(sigRaw);
  if (!sigs || !sigs.has(parsed.label)) {
    return { ok: false, operator: agent, keyid: null, reason: 'no Signature value for the declared label' };
  }
  const nowS = Math.floor(Date.now() / 1000);
  const created = parsed.params.created;
  if (typeof created !== 'number') {
    return { ok: false, operator: agent, keyid: null, reason: 'Signature-Input is missing created' };
  }
  if (created > nowS + MAX_CLOCK_SKEW_S) {
    return { ok: false, operator: agent, keyid: null, reason: 'attestation created in the future (clock skew)' };
  }
  if (nowS - created > MAX_ATTESTATION_AGE_S) {
    return { ok: false, operator: agent, keyid: null, reason: 'attestation expired' };
  }
  if (typeof parsed.params.expires === 'number' && parsed.params.expires <= nowS) {
    return { ok: false, operator: agent, keyid: null, reason: 'attestation expired' };
  }

  // Resolve the public key: keyid first, then the operator named by Signature-Agent.
  const keyid = parsed.params.keyid || null;
  let rec = null;
  if (keyid && registry.byKeyid.has(keyid)) rec = registry.byKeyid.get(keyid);
  else if (agent && registry.byOperator.has(agent)) rec = registry.byOperator.get(agent);
  let publicKeyMaterial = rec ? rec.publicKey : null;
  if (!publicKeyMaterial && keyid && /^https?:\/\//.test(keyid)) {
    try { publicKeyMaterial = await fetchKeyMaterial(keyid); } catch (e) {
      return { ok: false, operator: agent, keyid, reason: `could not fetch operator key from ${keyid}: ${e.message}` };
    }
  }
  if (!publicKeyMaterial) {
    return { ok: false, operator: agent, keyid, reason: 'no published key for this operator (not in the key registry)' };
  }
  let publicKey;
  try { publicKey = parsePublicKey(publicKeyMaterial); } catch (e) {
    return { ok: false, operator: agent, keyid, reason: `published key is unusable: ${e.message}` };
  }
  let base;
  try { base = buildSignatureBase(req, parsed); } catch (e) {
    return { ok: false, operator: agent, keyid, reason: e.message };
  }
  let sigBytes;
  try { sigBytes = Buffer.from(sigs.get(parsed.label), 'base64'); } catch (_) {
    return { ok: false, operator: agent, keyid, reason: 'Signature value is not valid base64' };
  }
  let ok = false;
  try { ok = crypto.verify(null, Buffer.from(base), publicKey, sigBytes); } catch (_) { ok = false; }
  if (!ok) return { ok: false, operator: agent, keyid, reason: 'signature does not verify against operator keys' };
  return { ok: true, operator: agent, keyid, reason: 'Web Bot Auth signature verified (Ed25519, RFC 9421)' };
}

/**
 * Sign a request the way a real agent would (used by the simulator and tests).
 * Returns { signatureInput, signature, signatureAgent } header values.
 */
function signRequest({ method, authority, path, query, agent, privateKeyPem, keyid, created }) {
  const components = ['@method', '@authority', '@path', '@query', 'signature-agent'];
  const createdAt = created || Math.floor(Date.now() / 1000);
  const params = `;created=${createdAt};expires=${createdAt + 300};keyid="${keyid}";tag="web-bot-auth"`;
  const lines = [
    `"@method": ${String(method || 'GET').toUpperCase()}`,
    `"@authority": ${String(authority || '').toLowerCase()}`,
    `"@path": ${path || '/'}`,
    `"@query": ${query || ''}`,
    `"signature-agent": ${agent}`,
    `"@signature-params": (${components.map((c) => `"${c}"`).join(' ')})${params}`,
  ];
  const base = lines.join('\n');
  const sig = crypto.sign(null, Buffer.from(base), privateKeyPem);
  return {
    signatureInput: `sig1=(${components.map((c) => `"${c}"`).join(' ')})${params}`,
    signature: `sig1=:${sig.toString('base64')}:`,
    signatureAgent: agent,
  };
}

/** Generate a fresh Ed25519 keypair (PEM SPKI public key + PEM PKCS8 private key). */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

module.exports = {
  loadRegistry, parseSignatureInput, parseSignature, buildSignatureBase,
  verifyWebBotAuth, signRequest, generateKeypair, REGISTRY_PATH,
};
