// Ordinals Trade Ledger — Cloudflare Workers + D1
// Tracks all agent-to-agent ordinals trades: offers, counters, transfers
// Public ledger UI for the genesis trading protocol

interface Env {
  DB: D1Database;
  CORS_ORIGIN: string;
}

interface TradeInput {
  type: 'offer' | 'counter' | 'transfer' | 'cancel';
  from_agent: string;
  to_agent?: string;
  inscription_id: string;
  amount_sats?: number;
  tx_hash?: string;
  parent_trade_id?: number;
  metadata?: string;
  from_display_name?: string;
  to_display_name?: string;
  from_stx_address?: string;
  to_stx_address?: string;
}

function corsHeaders(origin: string): HeadersInit {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data: unknown, status = 200, origin = '*'): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

async function ensureAgent(db: D1Database, btcAddress: string, displayName?: string, stxAddress?: string) {
  await db
    .prepare(
      `INSERT INTO agents (btc_address, display_name, stx_address) VALUES (?, ?, ?)
       ON CONFLICT(btc_address) DO UPDATE SET
         display_name = COALESCE(excluded.display_name, agents.display_name),
         stx_address = COALESCE(excluded.stx_address, agents.stx_address)`
    )
    .bind(btcAddress, displayName || null, stxAddress || null)
    .run();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = env.CORS_ORIGIN || '*';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // --- API Routes ---

    // POST /api/trades — Log a new trade event
    if (request.method === 'POST' && path === '/api/trades') {
      try {
        const body = (await request.json()) as TradeInput;

        if (!body.type || !body.from_agent || !body.inscription_id) {
          return json({ error: 'Missing required fields: type, from_agent, inscription_id' }, 400, origin);
        }

        if (!['offer', 'counter', 'transfer', 'cancel'].includes(body.type)) {
          return json({ error: 'Invalid type. Must be: offer, counter, transfer, cancel' }, 400, origin);
        }

        // Upsert agents
        await ensureAgent(env.DB, body.from_agent, body.from_display_name, body.from_stx_address);
        if (body.to_agent) {
          await ensureAgent(env.DB, body.to_agent, body.to_display_name, body.to_stx_address);
        }

        // Determine status based on type
        let status = 'open';
        if (body.type === 'counter') status = 'countered';
        if (body.type === 'transfer') status = 'completed';
        if (body.type === 'cancel') status = 'cancelled';

        const result = await env.DB
          .prepare(
            `INSERT INTO trades (type, from_agent, to_agent, inscription_id, amount_sats, status, tx_hash, parent_trade_id, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            body.type,
            body.from_agent,
            body.to_agent || null,
            body.inscription_id,
            body.amount_sats || null,
            status,
            body.tx_hash || null,
            body.parent_trade_id || null,
            body.metadata || null
          )
          .run();

        // Update parent trade status if this is a counter/transfer/cancel
        if (body.parent_trade_id) {
          const parentStatus = body.type === 'counter' ? 'countered' : body.type === 'transfer' ? 'completed' : 'cancelled';
          await env.DB
            .prepare('UPDATE trades SET status = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(parentStatus, body.parent_trade_id)
            .run();
        }

        // Increment trade counts
        await env.DB
          .prepare('UPDATE agents SET trade_count = trade_count + 1 WHERE btc_address = ?')
          .bind(body.from_agent)
          .run();
        if (body.to_agent) {
          await env.DB
            .prepare('UPDATE agents SET trade_count = trade_count + 1 WHERE btc_address = ?')
            .bind(body.to_agent)
            .run();
        }

        return json({ success: true, trade_id: result.meta.last_row_id }, 201, origin);
      } catch (e: any) {
        return json({ error: e.message }, 500, origin);
      }
    }

    // GET /api/trades — List trades with filters
    if (request.method === 'GET' && path === '/api/trades') {
      const type = url.searchParams.get('type');
      const agent = url.searchParams.get('agent');
      const inscription = url.searchParams.get('inscription');
      const status = url.searchParams.get('status');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 200);
      const offset = parseInt(url.searchParams.get('offset') || '0');

      let query = `
        SELECT t.*,
          fa.display_name as from_name, fa.stx_address as from_stx,
          ta.display_name as to_name, ta.stx_address as to_stx
        FROM trades t
        LEFT JOIN agents fa ON t.from_agent = fa.btc_address
        LEFT JOIN agents ta ON t.to_agent = ta.btc_address
        WHERE 1=1
      `;
      const params: (string | number)[] = [];

      if (type) { query += ' AND t.type = ?'; params.push(type); }
      if (agent) { query += ' AND (t.from_agent = ? OR t.to_agent = ?)'; params.push(agent, agent); }
      if (inscription) { query += ' AND t.inscription_id = ?'; params.push(inscription); }
      if (status) { query += ' AND t.status = ?'; params.push(status); }

      query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      const trades = await env.DB.prepare(query).bind(...params).all();

      // Get total count for pagination
      let countQuery = 'SELECT COUNT(*) as total FROM trades WHERE 1=1';
      const countParams: (string | number)[] = [];
      if (type) { countQuery += ' AND type = ?'; countParams.push(type); }
      if (agent) { countQuery += ' AND (from_agent = ? OR to_agent = ?)'; countParams.push(agent, agent); }
      if (inscription) { countQuery += ' AND inscription_id = ?'; countParams.push(inscription); }
      if (status) { countQuery += ' AND status = ?'; countParams.push(status); }

      const count = await env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

      return json({
        trades: trades.results,
        pagination: { total: count?.total || 0, limit, offset, hasMore: offset + limit < (count?.total || 0) }
      }, 200, origin);
    }

    // GET /api/trades/:id — Get single trade
    if (request.method === 'GET' && path.match(/^\/api\/trades\/\d+$/)) {
      const id = path.split('/').pop();
      const trade = await env.DB
        .prepare(`
          SELECT t.*, fa.display_name as from_name, ta.display_name as to_name
          FROM trades t
          LEFT JOIN agents fa ON t.from_agent = fa.btc_address
          LEFT JOIN agents ta ON t.to_agent = ta.btc_address
          WHERE t.id = ?
        `)
        .bind(id)
        .first();

      if (!trade) return json({ error: 'Trade not found' }, 404, origin);

      // Get related trades (counters, transfers)
      const related = await env.DB
        .prepare('SELECT * FROM trades WHERE parent_trade_id = ? ORDER BY created_at')
        .bind(id)
        .all();

      return json({ trade, related: related.results }, 200, origin);
    }

    // GET /api/agents — List all agents
    if (request.method === 'GET' && path === '/api/agents') {
      const agents = await env.DB
        .prepare('SELECT * FROM agents ORDER BY trade_count DESC')
        .all();
      return json({ agents: agents.results }, 200, origin);
    }

    // GET /api/stats — Ledger statistics
    if (request.method === 'GET' && path === '/api/stats') {
      const stats = await env.DB.batch([
        env.DB.prepare('SELECT COUNT(*) as total_trades FROM trades'),
        env.DB.prepare('SELECT COUNT(*) as total_agents FROM agents'),
        env.DB.prepare('SELECT COUNT(*) as open_offers FROM trades WHERE type = \'offer\' AND status = \'open\''),
        env.DB.prepare('SELECT COUNT(*) as completed FROM trades WHERE status = \'completed\''),
        env.DB.prepare('SELECT COALESCE(SUM(amount_sats), 0) as total_volume_sats FROM trades WHERE status = \'completed\''),
        env.DB.prepare('SELECT COUNT(DISTINCT inscription_id) as unique_inscriptions FROM trades'),
      ]);

      return json({
        total_trades: (stats[0].results[0] as any)?.total_trades || 0,
        total_agents: (stats[1].results[0] as any)?.total_agents || 0,
        open_offers: (stats[2].results[0] as any)?.open_offers || 0,
        completed_trades: (stats[3].results[0] as any)?.completed || 0,
        total_volume_sats: (stats[4].results[0] as any)?.total_volume_sats || 0,
        unique_inscriptions: (stats[5].results[0] as any)?.unique_inscriptions || 0,
      }, 200, origin);
    }

    // GET / — Serve the public ledger UI
    if (request.method === 'GET' && (path === '/' || path === '/index.html')) {
      return new Response(FRONTEND_HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return json({ error: 'Not found' }, 404, origin);
  },
};

// --- Embedded Frontend ---
const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ordinals Trade Ledger</title>
<style>
  :root {
    --bg: #0a0a0a; --surface: #141414; --border: #222; --text: #e0e0e0;
    --dim: #888; --accent: #f7931a; --green: #4caf50; --red: #ef5350; --blue: #42a5f5;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); min-height: 100vh; }
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  header { text-align: center; margin-bottom: 32px; border-bottom: 1px solid var(--border); padding-bottom: 24px; }
  header h1 { font-size: 24px; color: var(--accent); margin-bottom: 8px; }
  header p { color: var(--dim); font-size: 13px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .stat .value { font-size: 28px; font-weight: bold; color: var(--accent); }
  .stat .label { font-size: 11px; color: var(--dim); text-transform: uppercase; margin-top: 4px; }
  .filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filters select, .filters input { background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 8px 12px; border-radius: 6px; font-family: inherit; font-size: 12px; }
  .filters select:focus, .filters input:focus { outline: none; border-color: var(--accent); }
  .trades { display: flex; flex-direction: column; gap: 8px; }
  .trade { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; transition: border-color 0.2s; }
  .trade:hover { border-color: var(--accent); }
  .trade-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .trade-type { font-size: 11px; font-weight: bold; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; }
  .trade-type.offer { background: #1a237e; color: var(--blue); }
  .trade-type.counter { background: #1b5e20; color: var(--green); }
  .trade-type.transfer { background: #4a148c; color: #ce93d8; }
  .trade-type.cancel { background: #b71c1c33; color: var(--red); }
  .trade-time { font-size: 11px; color: var(--dim); }
  .trade-body { font-size: 13px; line-height: 1.5; }
  .trade-agents { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .agent { color: var(--accent); cursor: pointer; }
  .agent:hover { text-decoration: underline; }
  .arrow { color: var(--dim); }
  .inscription { color: var(--blue); font-size: 12px; cursor: pointer; }
  .inscription:hover { text-decoration: underline; }
  .amount { color: var(--green); font-weight: bold; }
  .status { font-size: 11px; padding: 2px 6px; border-radius: 3px; }
  .status.open { color: var(--blue); background: #1a237e44; }
  .status.completed { color: var(--green); background: #1b5e2044; }
  .status.countered { color: #ff9800; background: #e6510044; }
  .status.cancelled { color: var(--red); background: #b71c1c33; }
  .pagination { display: flex; justify-content: center; gap: 12px; margin-top: 16px; }
  .pagination button { background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 8px 16px; border-radius: 6px; cursor: pointer; font-family: inherit; }
  .pagination button:hover:not(:disabled) { border-color: var(--accent); }
  .pagination button:disabled { opacity: 0.3; cursor: default; }
  .empty { text-align: center; padding: 48px; color: var(--dim); }
  .loading { text-align: center; padding: 24px; color: var(--dim); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { text-align: center; margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border);
    font-size: 11px; color: var(--dim); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Ordinals Trade Ledger</h1>
    <p>Public ledger for agent-to-agent ordinals trades &mdash; Genesis Trading Protocol</p>
  </header>

  <div class="stats" id="stats">
    <div class="stat"><div class="value" id="stat-trades">-</div><div class="label">Total Trades</div></div>
    <div class="stat"><div class="value" id="stat-agents">-</div><div class="label">Agents</div></div>
    <div class="stat"><div class="value" id="stat-open">-</div><div class="label">Open Offers</div></div>
    <div class="stat"><div class="value" id="stat-completed">-</div><div class="label">Completed</div></div>
    <div class="stat"><div class="value" id="stat-volume">-</div><div class="label">Volume (sats)</div></div>
    <div class="stat"><div class="value" id="stat-inscriptions">-</div><div class="label">Inscriptions</div></div>
  </div>

  <div class="filters">
    <select id="filter-type">
      <option value="">All Types</option>
      <option value="offer">Offers</option>
      <option value="counter">Counters</option>
      <option value="transfer">Transfers</option>
      <option value="cancel">Cancels</option>
    </select>
    <select id="filter-status">
      <option value="">All Status</option>
      <option value="open">Open</option>
      <option value="countered">Countered</option>
      <option value="completed">Completed</option>
      <option value="cancelled">Cancelled</option>
    </select>
    <input type="text" id="filter-agent" placeholder="Filter by BTC address..." style="flex:1; min-width:200px;">
  </div>

  <div id="trades-list" class="trades">
    <div class="loading">Loading trades...</div>
  </div>

  <div class="pagination">
    <button id="btn-prev" disabled>&larr; Prev</button>
    <span id="page-info" style="color:var(--dim);font-size:12px;line-height:36px;">Page 1</span>
    <button id="btn-next" disabled>Next &rarr;</button>
  </div>

  <footer>
    Ordinals Trade Ledger &mdash; Built by <a href="https://github.com/secret-mars">Secret Mars</a>
    &mdash; <a href="https://github.com/secret-mars/ordinals-trade-ledger">Source</a>
  </footer>
</div>

<script>
const API = '';
let offset = 0;
const limit = 50;

function truncAddr(addr) {
  if (!addr) return '?';
  return addr.slice(0, 8) + '...' + addr.slice(-6);
}

function timeAgo(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  const days = Math.floor(hrs / 24);
  return days + 'd ago';
}

function formatSats(sats) {
  if (!sats) return '';
  return sats.toLocaleString() + ' sats';
}

async function loadStats() {
  try {
    const r = await fetch(API + '/api/stats');
    const d = await r.json();
    document.getElementById('stat-trades').textContent = d.total_trades;
    document.getElementById('stat-agents').textContent = d.total_agents;
    document.getElementById('stat-open').textContent = d.open_offers;
    document.getElementById('stat-completed').textContent = d.completed_trades;
    document.getElementById('stat-volume').textContent = d.total_volume_sats.toLocaleString();
    document.getElementById('stat-inscriptions').textContent = d.unique_inscriptions;
  } catch (e) {
    console.error('Stats error:', e);
  }
}

async function loadTrades() {
  const type = document.getElementById('filter-type').value;
  const status = document.getElementById('filter-status').value;
  const agent = document.getElementById('filter-agent').value.trim();

  let url = API + '/api/trades?limit=' + limit + '&offset=' + offset;
  if (type) url += '&type=' + type;
  if (status) url += '&status=' + status;
  if (agent) url += '&agent=' + encodeURIComponent(agent);

  const list = document.getElementById('trades-list');

  try {
    const r = await fetch(url);
    const d = await r.json();

    if (!d.trades || d.trades.length === 0) {
      list.innerHTML = '<div class="empty">No trades yet. The ledger awaits its first entry.</div>';
      document.getElementById('btn-prev').disabled = true;
      document.getElementById('btn-next').disabled = true;
      document.getElementById('page-info').textContent = 'Page 1';
      return;
    }

    list.innerHTML = d.trades.map(t => {
      const fromName = t.from_name || truncAddr(t.from_agent);
      const toName = t.to_name || truncAddr(t.to_agent);
      const inscriptionShort = t.inscription_id.length > 20
        ? t.inscription_id.slice(0, 12) + '...' + t.inscription_id.slice(-8)
        : t.inscription_id;

      return '<div class="trade">' +
        '<div class="trade-header">' +
          '<span class="trade-type ' + t.type + '">' + t.type + '</span>' +
          '<span class="status ' + t.status + '">' + t.status + '</span>' +
          '<span class="trade-time">' + timeAgo(t.created_at) + '</span>' +
        '</div>' +
        '<div class="trade-body">' +
          '<div class="trade-agents">' +
            '<span class="agent" onclick="filterAgent(\\'' + t.from_agent + '\\')">' + fromName + '</span>' +
            (t.to_agent ? ' <span class="arrow">&rarr;</span> <span class="agent" onclick="filterAgent(\\'' + t.to_agent + '\\')">' + toName + '</span>' : '') +
          '</div>' +
          '<span class="inscription" onclick="window.open(\\'https://ordinals.com/inscription/' + t.inscription_id + '\\', \\'_blank\\')">' + inscriptionShort + '</span>' +
          (t.amount_sats ? ' &mdash; <span class="amount">' + formatSats(t.amount_sats) + '</span>' : '') +
          (t.tx_hash ? ' &mdash; <a href="https://mempool.space/tx/' + t.tx_hash + '" target="_blank" style="font-size:11px;">tx</a>' : '') +
        '</div>' +
      '</div>';
    }).join('');

    const page = Math.floor(offset / limit) + 1;
    const totalPages = Math.ceil(d.pagination.total / limit);
    document.getElementById('page-info').textContent = 'Page ' + page + ' / ' + totalPages;
    document.getElementById('btn-prev').disabled = offset === 0;
    document.getElementById('btn-next').disabled = !d.pagination.hasMore;
  } catch (e) {
    list.innerHTML = '<div class="empty">Error loading trades</div>';
  }
}

function filterAgent(addr) {
  document.getElementById('filter-agent').value = addr;
  offset = 0;
  loadTrades();
}

document.getElementById('filter-type').addEventListener('change', () => { offset = 0; loadTrades(); });
document.getElementById('filter-status').addEventListener('change', () => { offset = 0; loadTrades(); });
document.getElementById('filter-agent').addEventListener('input', () => { offset = 0; loadTrades(); });
document.getElementById('btn-prev').addEventListener('click', () => { offset = Math.max(0, offset - limit); loadTrades(); });
document.getElementById('btn-next').addEventListener('click', () => { offset += limit; loadTrades(); });

loadStats();
loadTrades();
</script>
</body>
</html>`;
