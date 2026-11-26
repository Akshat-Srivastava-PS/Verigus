// Published agent contract (agents.txt-style) + sanctioned API/MCP door
// (blueprint Phase 2).
//
// A site protected by Verigus publishes what agents MAY do here, so a
// legitimate agent never has to guess — and the guard can hold agents to
// the published contract. Served at GET /agents.txt (plain text) and as
// JSON at GET /api/agent-contract.
//
// The sanctioned door is a minimal JSON-RPC 2.0 API at POST /api/agent:
//   tools/list  -> the sanctioned tools and their schemas
//   tools/call  -> call one tool (params validated; order-status calls
//                  require a delegated-authority mandate)
// The door is not a bypass: every call still passes through the guard
// like any other request.
'use strict';

const config = require('./config');
const delegation = require('./delegation');

function agentContractText() {
  const lines = [
    '# Agent contract for ' + config.siteName,
    '# Published by Verigus — "Every agent verified, every threat remembered."',
    '#',
    '# This site welcomes identified AI agents that state an authentic purpose',
    '# and stay inside it. Everything else is observed, scored, and — when the',
    '# risk demands it — challenged, sandboxed, or permanently blocked.',
    '',
    'User-Agent: *',
    'Allow: /products',
    'Allow: /pricing',
    'Allow: /search',
    'Allow: /api/v1/products',
    'Allow: /api/agent',
    'Disallow: /.env',
    'Disallow: /.git',
    'Disallow: /config',
    'Disallow: /backup',
    'Disallow: /admin',
    'Disallow: /account/reset',
    '',
    '# Permitted purposes: ' + config.permittedPurposes.join(', '),
    '# Authentication: Web Bot Auth (Ed25519, RFC 9421) — send Signature-Agent,',
    '#   Signature-Input and Signature headers. Unsigned agents are observed',
    '#   and scored; they are never fast-pathed.',
    '# Delegated authority: transactions (orders) require a signed AP2-style',
    '#   mandate from the principal (X-Agent-Mandate header).',
    '# Sanctioned API/MCP door: POST /api/agent (JSON-RPC 2.0, tools/list + tools/call)',
    '# Rate limits: the guard scores velocity against the site baseline; bursts',
    '#   far above normal agent pace are throttled, then blocked.',
    '# Contact: see the site operator. Blocks are final and permanent.',
  ];
  return lines.join('\n') + '\n';
}

function agentContractJson() {
  return {
    site: config.siteName,
    allow: ['/products', '/pricing', '/search', '/api/v1/products', '/api/agent'],
    disallow: ['/.env', '/.git', '/config', '/backup', '/admin', '/account/reset'],
    permittedPurposes: config.permittedPurposes,
    authentication: 'Web Bot Auth (Ed25519, RFC 9421): Signature-Agent + Signature-Input + Signature',
    delegatedAuthority: 'AP2-style mandate required for transactions (X-Agent-Mandate header)',
    mcpDoor: '/api/agent (JSON-RPC 2.0: tools/list, tools/call)',
  };
}

// Sanctioned tools. get_order_status requires a delegated mandate.
const TOOLS = [
  {
    name: 'list_products',
    description: 'List the shop catalog (products and prices).',
    inputSchema: { type: 'object', properties: {}, required: [] },
    requiresMandate: false,
  },
  {
    name: 'search_products',
    description: 'Search the catalog by name.',
    inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] },
    requiresMandate: false,
  },
  {
    name: 'get_order_status',
    description: 'Look up an order status. Acts on a customer behalf — requires a delegated-authority mandate.',
    inputSchema: { type: 'object', properties: { order_id: { type: 'string' } }, required: ['order_id'] },
    requiresMandate: true,
  },
];

/**
 * Handle one JSON-RPC 2.0 call to the sanctioned door.
 * ctx: { products, orders, mandate (verified mandate object or null), registry }
 * Returns a JSON-RPC response object.
 */
function handleMcpCall(body, ctx) {
  const id = body && body.id !== undefined ? body.id : null;
  const error = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  if (!body || typeof body !== 'object' || body.jsonrpc !== '2.0' || typeof body.method !== 'string') {
    return error(-32600, 'Invalid Request: expected JSON-RPC 2.0 with a method');
  }
  if (body.method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  }
  if (body.method === 'tools/call') {
    const params = (body.params && typeof body.params === 'object') ? body.params : {};
    const tool = TOOLS.find((t) => t.name === params.name);
    if (!tool) return error(-32602, `Unknown tool "${params.name}"`);
    const args = (params.arguments && typeof params.arguments === 'object') ? params.arguments : {};
    for (const req of tool.inputSchema.required) {
      if (args[req] === undefined || args[req] === null || args[req] === '') {
        return error(-32602, `Tool "${tool.name}" requires argument "${req}"`);
      }
    }
    if (tool.requiresMandate) {
      if (!ctx.mandate || !ctx.mandate.ok) {
        return error(-32001, 'Delegated authority required: get_order_status needs a verified AP2 mandate (X-Agent-Mandate header)');
      }
      if (!delegation.mandateCovers(ctx.mandate.mandate, { endpoint: '/api/v1/orders', action: 'GET' })) {
        return error(-32001, 'Mandate scope does not cover order-status lookup');
      }
    }
    if (tool.name === 'list_products') {
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(ctx.products || []) }] } };
    }
    if (tool.name === 'search_products') {
      const q = String(args.q).toLowerCase();
      const results = (ctx.products || []).filter((p) => p.name.toLowerCase().includes(q));
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(results) }] } };
    }
    if (tool.name === 'get_order_status') {
      const orders = ctx.orders || [];
      const found = orders.find((o) => o.id === args.order_id);
      if (!found) return error(-32602, `No such order "${args.order_id}"`);
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(found) }] } };
    }
    return error(-32601, 'Method not found');
  }
  return error(-32601, `Method "${body.method}" not found (available: tools/list, tools/call)`);
}

module.exports = { agentContractText, agentContractJson, TOOLS, handleMcpCall };
