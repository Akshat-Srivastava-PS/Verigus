// Self-serve onboarding (blueprint Phase 2): one command, guard live.
//
//   node scripts/onboard.js --site myshop.example.com [--out ./verigus.site.json]
//
// Generates a site id and an Ed25519 keypair for the site's own operator
// identity (the key its own agents use for Web Bot Auth), writes the
// public part to verigus.site.json, the private key to verigus.site.key.json
// (0600 — keep it secret; it signs your agents' attestations), and prints
// the one-line install, the Render Blueprint snippet, and the dashboard URL.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--site' && argv[i + 1]) out.site = argv[++i];
    else if (argv[i] === '--out' && argv[i + 1]) out.out = argv[++i];
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.site) {
    console.error('Usage: node scripts/onboard.js --site myshop.example.com [--out ./verigus.site.json]');
    process.exit(1);
  }
  const siteId = `site-${crypto.randomBytes(8).toString('hex')}`;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const outPath = args.out || path.join(process.cwd(), 'verigus.site.json');
  const keyPath = outPath.replace(/\.json$/, '.key.json');
  const siteConfig = {
    site: args.site,
    siteId,
    createdAt: new Date().toISOString(),
    operator: args.site,
    publicKey: publicKeyPem,
    guard: {
      install: 'curl -fsSL https://raw.githubusercontent.com/Akshat-Srivastava-PS/Verigus/main/install.sh | bash',
      dashboard: 'https://verigus.onrender.com/dashboard',
    },
    note: 'Register this public key in the guard operator-keys registry (src/data/operator-keys.json) under your operator name so your agents verify.',
  };
  fs.writeFileSync(outPath, JSON.stringify(siteConfig, null, 2));
  fs.writeFileSync(keyPath, JSON.stringify({ site: args.site, siteId, privateKey: privateKeyPem }, null, 2), { mode: 0o600 });
  console.log(`Site onboarded: ${args.site} (${siteId})`);
  console.log(`  Site config: ${outPath}`);
  console.log(`  Private key: ${keyPath} (0600 — keep it secret; it signs your agents' attestations)`);
  console.log('');
  console.log('  One-line install:');
  console.log('    curl -fsSL https://raw.githubusercontent.com/Akshat-Srivastava-PS/Verigus/main/install.sh | bash');
  console.log('');
  console.log('  Render Blueprint (render.yaml) deploys the guard as a free Web Service:');
  console.log('    services: [{ type: web, name: verigus, env: node, plan: free,');
  console.log('                 buildCommand: npm install, startCommand: npm start }]');
  console.log('');
  console.log('  The guard starts in OBSERVE mode and decides itself when to enforce.');
  console.log('  Dashboard: https://verigus.onrender.com/dashboard (read-only)');
}

if (require.main === module) main();
module.exports = { parseArgs };
