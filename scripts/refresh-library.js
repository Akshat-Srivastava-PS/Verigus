// Manual trigger for the Threat Library daily refresh (same cycle the
// guard runs on schedule every 24h). Usage: npm run refresh-library
'use strict';

const { ThreatLibrary } = require('../src/threatLibrary');
const { AgentPulseFeed } = require('../src/agentpulse');

async function main() {
  const feed = new AgentPulseFeed();
  const library = new ThreatLibrary(feed);
  console.log(`Library v${library.version} (${library.entries.length} entries) before refresh.`);
  const report = await library.dailyRefresh();
  console.log('Daily refresh complete:', JSON.stringify(report, null, 2));
  console.log(`Library v${library.version} (${library.entries.length} entries) after refresh.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
