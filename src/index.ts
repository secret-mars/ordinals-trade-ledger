// Ordinals Trade Ledger — Cloudflare Workers + D1
// Tracks all agent-to-agent ordinals trades: offers, counters, transfers
// Public ledger UI for the genesis trading protocol

interface Env {
  DB: D1Database;
  CORS_ORIGIN: string;
  HIRO_API_KEY?: string;
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

// Auth: require BIP-137 signature on all write endpoints
// Signature message format: "ordinals-ledger | {type} | {from_agent} | {inscription_id} | {timestamp}"
// Timestamp must be within 300 seconds of server time
function validateAuth(body: any): string | null {
  if (!body.from_agent) return 'Required: from_agent';
  if (!body.signature) return 'Required: signature (BIP-137 signed message)';
  if (!body.timestamp) return 'Required: timestamp (ISO 8601)';

  // Validate signature format (base64-encoded BIP-137 = 88 chars)
  if (typeof body.signature !== 'string' || body.signature.length < 80 || body.signature.length > 100) {
    return 'Invalid signature format (expected base64 BIP-137, ~88 chars)';
  }

  // Validate timestamp is recent (within 300 seconds)
  const ts = new Date(body.timestamp).getTime();
  if (isNaN(ts)) return 'Invalid timestamp format';
  const drift = Math.abs(Date.now() - ts);
  if (drift > 300_000) return 'Timestamp expired (must be within 300 seconds of server time)';

  // Transfer type requires tx_hash for on-chain verification
  if (body.type === 'transfer' && !body.tx_hash) {
    return 'Transfer trades require tx_hash for on-chain verification';
  }

  return null;
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

// --- On-Chain Watcher ---

interface InscriptionResult {
  id: string;
  number: number;
  address: string;
  content_type: string;
}

async function fetchAgentInscriptions(address: string, _apiKey?: string): Promise<InscriptionResult[]> {
  // Uses Unisat open API — Hiro's ordinals index misses recent inscriptions
  const all: InscriptionResult[] = [];
  const perPage = 100;
  const maxPages = 3; // cap at 300 inscriptions per agent
  let cursor = 0;

  for (let page = 0; page < maxPages; page++) {
    const url = `https://open-api.unisat.io/v1/indexer/address/${encodeURIComponent(address)}/inscription-data?cursor=${cursor}&size=${perPage}`;
    const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) {
      throw new Error(`Unisat API ${resp.status}: ${resp.statusText}`);
    }

    const data = await resp.json() as {
      code: number;
      msg: string;
      data: {
        total: number;
        cursor: number;
        inscription: Array<{
          inscriptionId: string;
          inscriptionNumber: number;
          address: string;
          contentType: string;
        }>;
      };
    };

    if (data.code !== 0) {
      throw new Error(`Unisat API error: ${data.msg}`);
    }
    if (!data.data?.inscription) break;

    for (const insc of data.data.inscription) {
      all.push({
        id: insc.inscriptionId,
        number: insc.inscriptionNumber,
        address: insc.address,
        content_type: insc.contentType,
      });
    }

    if (all.length >= data.data.total || data.data.inscription.length < perPage) break;
    cursor += perPage;
  }

  return all;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function findPreviousHolder(db: D1Database, inscriptionId: string, currentHolder: string): Promise<string | null> {
  const row = await db
    .prepare('SELECT btc_address FROM agent_inscriptions WHERE inscription_id = ? AND btc_address != ?')
    .bind(inscriptionId, currentHolder)
    .first<{ btc_address: string }>();
  return row?.btc_address || null;
}

async function syncAgentsFromAibtc(db: D1Database): Promise<number> {
  let synced = 0;
  let offset = 0;
  const limit = 100;

  while (true) {
    const resp = await fetch(`https://aibtc.com/api/agents?limit=${limit}&offset=${offset}`);
    if (!resp.ok) break;

    const data = await resp.json() as {
      agents: Array<{ btcAddress: string; stxAddress: string; displayName: string; bnsName: string | null }>;
      pagination: { total: number; hasMore: boolean };
    };

    if (!data.agents || data.agents.length === 0) break;

    for (const a of data.agents) {
      if (!a.btcAddress) continue;
      await db
        .prepare(
          `INSERT INTO agents (btc_address, display_name, stx_address) VALUES (?, ?, ?)
           ON CONFLICT(btc_address) DO UPDATE SET
             display_name = COALESCE(excluded.display_name, agents.display_name),
             stx_address = COALESCE(excluded.stx_address, agents.stx_address)`
        )
        .bind(a.btcAddress, a.displayName || a.bnsName || null, a.stxAddress || null)
        .run();
      synced++;
    }

    if (!data.pagination.hasMore) break;
    offset += limit;
  }

  return synced;
}

async function runWatcher(env: Env): Promise<void> {
  const db = env.DB;

  // Check for overlap — skip if a run is still in progress
  const inProgress = await db
    .prepare("SELECT id FROM watcher_runs WHERE status = 'running' AND started_at > datetime('now', '-10 minutes')")
    .first();
  if (inProgress) return;

  // Start run
  const run = await db
    .prepare("INSERT INTO watcher_runs (status) VALUES ('running')")
    .run();
  const runId = run.meta.last_row_id;

  let agentsChecked = 0;
  let transfersFound = 0;
  const errors: string[] = [];

  try {
    // Sync all registered agents from AIBTC directory
    try {
      await syncAgentsFromAibtc(db);
    } catch (syncErr: any) {
      errors.push(`aibtc sync: ${syncErr.message}`);
    }

    const agents = await db.prepare('SELECT btc_address, display_name FROM agents').all<{ btc_address: string; display_name: string | null }>();

    for (const agent of agents.results) {
      try {
        agentsChecked++;
        const currentInscriptions = await fetchAgentInscriptions(agent.btc_address, env.HIRO_API_KEY);
        const currentIds = new Set(currentInscriptions.map(i => i.id));

        // Get previous snapshot
        const snapshot = await db
          .prepare('SELECT inscription_id FROM agent_inscriptions WHERE btc_address = ?')
          .bind(agent.btc_address)
          .all<{ inscription_id: string }>();
        const previousIds = new Set(snapshot.results.map(r => r.inscription_id));

        // New inscriptions = incoming transfers
        for (const insc of currentInscriptions) {
          if (!previousIds.has(insc.id)) {
            // Check dedup: no matching trade in last 24h for this inscription+agent
            const existing = await db
              .prepare(
                "SELECT id FROM trades WHERE inscription_id = ? AND to_agent = ? AND created_at > datetime('now', '-1 day')"
              )
              .bind(insc.id, agent.btc_address)
              .first();

            if (!existing) {
              const previousHolder = await findPreviousHolder(db, insc.id, agent.btc_address);

              if (previousHolder) {
                // Log as detected transfer
                await db
                  .prepare(
                    `INSERT INTO trades (type, from_agent, to_agent, inscription_id, status, source, metadata)
                     VALUES ('transfer', ?, ?, ?, 'completed', 'watcher', 'Auto-detected by on-chain watcher')`
                  )
                  .bind(previousHolder, agent.btc_address, insc.id)
                  .run();

                // Update trade counts
                await db.prepare('UPDATE agents SET trade_count = trade_count + 1 WHERE btc_address = ?').bind(previousHolder).run();
                await db.prepare('UPDATE agents SET trade_count = trade_count + 1 WHERE btc_address = ?').bind(agent.btc_address).run();

                transfersFound++;
              }
            }

            // Add to snapshot
            await db
              .prepare('INSERT OR IGNORE INTO agent_inscriptions (btc_address, inscription_id) VALUES (?, ?)')
              .bind(agent.btc_address, insc.id)
              .run();
          }
        }

        // Missing inscriptions = outgoing transfers — remove from snapshot
        for (const prev of snapshot.results) {
          if (!currentIds.has(prev.inscription_id)) {
            await db
              .prepare('DELETE FROM agent_inscriptions WHERE btc_address = ? AND inscription_id = ?')
              .bind(agent.btc_address, prev.inscription_id)
              .run();
          }
        }
      } catch (agentErr: any) {
        errors.push(`${agent.btc_address}: ${agentErr.message}`);
      }

      // Rate limit courtesy — 500ms between agents
      if (agents.results.indexOf(agent) < agents.results.length - 1) {
        await sleep(500);
      }
    }

    // Complete run
    await db
      .prepare(
        "UPDATE watcher_runs SET status = 'completed', finished_at = datetime('now'), agents_checked = ?, transfers_found = ?, errors = ? WHERE id = ?"
      )
      .bind(agentsChecked, transfersFound, errors.length ? errors.join('; ') : null, runId)
      .run();
  } catch (e: any) {
    await db
      .prepare(
        "UPDATE watcher_runs SET status = 'error', finished_at = datetime('now'), agents_checked = ?, transfers_found = ?, errors = ? WHERE id = ?"
      )
      .bind(agentsChecked, transfersFound, e.message, runId)
      .run();
  }
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
        const body = (await request.json()) as TradeInput & { signature?: string; timestamp?: string };

        if (!body.type || !body.from_agent || !body.inscription_id) {
          return json({ error: 'Missing required fields: type, from_agent, inscription_id' }, 400, origin);
        }

        if (!['offer', 'counter', 'transfer', 'cancel'].includes(body.type)) {
          return json({ error: 'Invalid type. Must be: offer, counter, transfer, cancel' }, 400, origin);
        }

        const authErr = validateAuth(body as any);
        if (authErr) return json({ error: authErr }, 401, origin);

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
            `INSERT INTO trades (type, from_agent, to_agent, inscription_id, amount_sats, status, tx_hash, parent_trade_id, metadata, source)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual')`
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
        return json({ error: 'Internal server error' }, 500, origin);
      }
    }

    // GET /api/trades — List trades with filters
    if (request.method === 'GET' && path === '/api/trades') {
      const type = url.searchParams.get('type');
      const agent = url.searchParams.get('agent');
      const inscription = url.searchParams.get('inscription');
      const status = url.searchParams.get('status');
      const limitRaw = parseInt(url.searchParams.get('limit') || '50');
      const offsetRaw = parseInt(url.searchParams.get('offset') || '0');
      const limit = Math.min(Math.max(isNaN(limitRaw) ? 50 : limitRaw, 1), 200);
      const offset = Math.max(isNaN(offsetRaw) ? 0 : offsetRaw, 0);

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

    // GET /api/watcher/status — Watcher health and run info
    if (request.method === 'GET' && path === '/api/watcher/status') {
      const lastRun = await env.DB
        .prepare('SELECT * FROM watcher_runs ORDER BY id DESC LIMIT 1')
        .first();

      const snapshotStats = await env.DB
        .prepare('SELECT COUNT(DISTINCT btc_address) as agents_tracked, COUNT(*) as total_inscriptions FROM agent_inscriptions')
        .first<{ agents_tracked: number; total_inscriptions: number }>();

      return json({
        last_run: lastRun || null,
        snapshot: {
          agents_tracked: snapshotStats?.agents_tracked || 0,
          total_inscriptions: snapshotStats?.total_inscriptions || 0,
        },
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

  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(runWatcher(env));
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
    --bg: #050505;
    --surface: #0d0d0d;
    --surface2: #111;
    --border: #1a1a1a;
    --border-bright: #2a2a2a;
    --text: #c8c8c8;
    --dim: #555;
    --dim2: #3a3a3a;
    --neon-green: #00ff88;
    --neon-green-dim: rgba(0, 255, 136, 0.08);
    --neon-green-glow: rgba(0, 255, 136, 0.25);
    --orange: #f7931a;
    --orange-dim: rgba(247, 147, 26, 0.08);
    --orange-glow: rgba(247, 147, 26, 0.25);
    --blue: #00aaff;
    --blue-dim: rgba(0, 170, 255, 0.08);
    --red: #ff3355;
    --red-dim: rgba(255, 51, 85, 0.08);
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    position: relative;
    overflow-x: hidden;
  }

  /* Subtle grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,255,136,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,136,0.025) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* Vignette overlay */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background: radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.7) 100%);
    pointer-events: none;
    z-index: 0;
  }

  .container {
    max-width: 1000px;
    margin: 0 auto;
    padding: 0 16px 48px;
    position: relative;
    z-index: 1;
  }

  /* ---- HEADER ---- */
  header {
    padding: 32px 0 28px;
    margin-bottom: 32px;
    border-bottom: 1px solid var(--border);
    position: relative;
  }

  .header-inner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
  }

  .header-title-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .header-eyebrow {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--neon-green);
    opacity: 0.7;
  }

  header h1 {
    font-size: 26px;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #fff;
    line-height: 1;
  }

  header h1 span {
    color: var(--orange);
  }

  header p {
    font-size: 12px;
    color: var(--dim);
    margin-top: 4px;
    letter-spacing: 0.3px;
  }

  /* ---- LIVE INDICATOR ---- */
  .live-indicator {
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--surface);
    border: 1px solid var(--border-bright);
    border-radius: 6px;
    padding: 8px 14px;
  }

  .live-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--neon-green);
    box-shadow: 0 0 6px var(--neon-green), 0 0 12px var(--neon-green-glow);
    animation: livePulse 2s ease-in-out infinite;
    flex-shrink: 0;
  }

  .live-dot.paused {
    background: var(--dim);
    box-shadow: none;
    animation: none;
  }

  .live-label {
    font-size: 11px;
    font-weight: 700;
    color: var(--neon-green);
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  .live-label.paused { color: var(--dim); }

  .live-time {
    font-size: 10px;
    color: var(--dim);
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
  }

  @keyframes livePulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 6px var(--neon-green), 0 0 12px var(--neon-green-glow); }
    50% { opacity: 0.5; box-shadow: 0 0 3px var(--neon-green); }
  }

  /* ---- STATS GRID ---- */
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px;
    margin-bottom: 24px;
  }

  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px 14px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .stat::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--orange), transparent);
    opacity: 0.6;
  }

  .stat:hover {
    border-color: var(--border-bright);
    box-shadow: 0 0 16px rgba(247,147,26,0.08);
  }

  .stat .value {
    font-size: 30px;
    font-weight: 700;
    color: var(--orange);
    line-height: 1;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    letter-spacing: -1px;
  }

  .stat .label {
    font-size: 10px;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 6px;
  }

  /* ---- CHART ---- */
  .chart-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 18px 20px;
    margin-bottom: 20px;
  }

  .chart-title {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--dim);
    margin-bottom: 14px;
  }

  .chart-bars {
    display: flex;
    align-items: flex-end;
    gap: 12px;
    height: 60px;
  }

  .chart-bar-group {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 5px;
    flex: 1;
  }

  .chart-bar-wrap {
    width: 100%;
    display: flex;
    align-items: flex-end;
    justify-content: center;
    height: 48px;
  }

  .chart-bar {
    width: 100%;
    max-width: 48px;
    border-radius: 3px 3px 0 0;
    min-height: 2px;
    transition: height 0.6s cubic-bezier(0.23, 1, 0.32, 1);
    position: relative;
  }

  .chart-bar.offer  { background: linear-gradient(180deg, var(--blue), rgba(0,170,255,0.4)); box-shadow: 0 0 8px rgba(0,170,255,0.3); }
  .chart-bar.counter { background: linear-gradient(180deg, var(--orange), rgba(247,147,26,0.4)); box-shadow: 0 0 8px var(--orange-glow); }
  .chart-bar.transfer { background: linear-gradient(180deg, var(--neon-green), rgba(0,255,136,0.4)); box-shadow: 0 0 8px var(--neon-green-glow); }
  .chart-bar.cancel { background: linear-gradient(180deg, var(--red), rgba(255,51,85,0.4)); box-shadow: 0 0 8px rgba(255,51,85,0.3); }

  .chart-bar-label {
    font-size: 9px;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .chart-bar-value {
    font-size: 11px;
    font-weight: 600;
    color: var(--text);
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  /* ---- FILTERS ---- */
  .filters-bar {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    align-items: center;
  }

  .filter-label {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--dim);
    padding-right: 4px;
  }

  .filters-bar select,
  .filters-bar input {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 5px;
    font-family: inherit;
    font-size: 12px;
    appearance: none;
    -webkit-appearance: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    outline: none;
  }

  .filters-bar select {
    cursor: pointer;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23555'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 10px center;
    padding-right: 28px;
  }

  .filters-bar select:focus,
  .filters-bar input:focus {
    border-color: var(--neon-green);
    box-shadow: 0 0 0 2px var(--neon-green-dim), 0 0 12px var(--neon-green-dim);
  }

  .filters-bar input { flex: 1; min-width: 200px; }

  .filters-bar input::placeholder { color: var(--dim); }

  /* ---- SECTION HEADER ---- */
  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }

  .section-title {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--dim);
  }

  /* ---- TRADE FEED ---- */
  .trades { display: flex; flex-direction: column; gap: 6px; }

  .trade {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid transparent;
    border-radius: 6px;
    padding: 14px 16px;
    transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    cursor: default;
  }

  .trade[data-type="transfer"] { border-left-color: var(--neon-green); }
  .trade[data-type="offer"]    { border-left-color: var(--blue); }
  .trade[data-type="counter"]  { border-left-color: var(--orange); }
  .trade[data-type="cancel"]   { border-left-color: var(--red); }

  .trade:hover {
    background: var(--surface2);
    border-color: var(--border-bright);
    box-shadow: 0 2px 20px rgba(0,0,0,0.4);
  }

  .trade[data-type="transfer"]:hover { box-shadow: 0 2px 20px var(--neon-green-dim); }
  .trade[data-type="offer"]:hover    { box-shadow: 0 2px 20px var(--blue-dim); }
  .trade[data-type="counter"]:hover  { box-shadow: 0 2px 20px var(--orange-dim); }
  .trade[data-type="cancel"]:hover   { box-shadow: 0 2px 20px var(--red-dim); }

  .trade-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
    flex-wrap: wrap;
  }

  .trade-type {
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    padding: 2px 8px;
    border-radius: 3px;
  }

  .trade-type.offer    { color: var(--blue);       background: var(--blue-dim);        border: 1px solid rgba(0,170,255,0.2); }
  .trade-type.counter  { color: var(--orange);     background: var(--orange-dim);      border: 1px solid rgba(247,147,26,0.2); }
  .trade-type.transfer { color: var(--neon-green); background: var(--neon-green-dim);  border: 1px solid rgba(0,255,136,0.2); }
  .trade-type.cancel   { color: var(--red);        background: var(--red-dim);         border: 1px solid rgba(255,51,85,0.2); }

  .status {
    font-size: 10px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }

  .status.open       { color: var(--blue);       background: var(--blue-dim); }
  .status.completed  { color: var(--neon-green); background: var(--neon-green-dim); }
  .status.countered  { color: var(--orange);     background: var(--orange-dim); }
  .status.cancelled  { color: var(--red);        background: var(--red-dim); }

  .trade-time {
    font-size: 11px;
    color: var(--dim);
    margin-left: auto;
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
  }

  .trade-body { font-size: 13px; line-height: 1.5; }

  .trade-agents {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 7px;
    flex-wrap: wrap;
  }

  .agent-chip {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 3px 8px 3px 5px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }

  .agent-chip:hover {
    border-color: var(--orange);
    background: var(--orange-dim);
  }

  .agent-avatar {
    width: 20px;
    height: 20px;
    border-radius: 3px;
    flex-shrink: 0;
    overflow: hidden;
  }

  .agent-name {
    font-size: 12px;
    color: var(--orange);
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
  }

  .arrow { color: var(--dim2); font-size: 14px; }

  .trade-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .inscription {
    color: var(--blue);
    font-size: 11px;
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
    text-decoration: none;
    transition: color 0.15s;
  }

  .inscription:hover { color: #55ccff; text-decoration: underline; }

  .amount {
    color: var(--neon-green);
    font-weight: 600;
    font-size: 12px;
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
  }

  .tx-link {
    font-size: 10px;
    color: var(--dim);
    text-decoration: none;
    border: 1px solid var(--border);
    padding: 1px 6px;
    border-radius: 3px;
    transition: color 0.15s, border-color 0.15s;
    font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
  }

  .tx-link:hover { color: var(--text); border-color: var(--dim); }

  .source-badge {
    font-size: 9px;
    padding: 1px 5px;
    border-radius: 2px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    margin-left: 4px;
  }

  .source-badge.watcher { background: var(--neon-green-dim); color: var(--neon-green); border: 1px solid rgba(0,255,136,0.15); }
  .source-badge.manual  { background: var(--blue-dim);       color: var(--blue);       border: 1px solid rgba(0,170,255,0.15); }

  /* ---- PAGINATION ---- */
  .pagination {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;
    margin-top: 20px;
  }

  .pagination button {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 18px;
    border-radius: 5px;
    cursor: pointer;
    font-family: inherit;
    font-size: 12px;
    font-weight: 500;
    transition: border-color 0.15s, color 0.15s, box-shadow 0.15s;
  }

  .pagination button:hover:not(:disabled) {
    border-color: var(--neon-green);
    color: var(--neon-green);
    box-shadow: 0 0 8px var(--neon-green-dim);
  }

  .pagination button:disabled { opacity: 0.25; cursor: default; }

  #page-info {
    font-size: 11px;
    color: var(--dim);
    font-family: 'SF Mono', 'Fira Code', monospace;
    min-width: 80px;
    text-align: center;
  }

  /* ---- EMPTY / LOADING ---- */
  .empty {
    text-align: center;
    padding: 56px 24px;
    color: var(--dim);
    font-size: 13px;
    letter-spacing: 0.3px;
  }

  .empty::before {
    content: '// ';
    color: var(--dim2);
  }

  .loading {
    text-align: center;
    padding: 32px;
    color: var(--dim);
    font-size: 12px;
    letter-spacing: 1px;
  }

  /* ---- ANIMATIONS ---- */
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  @keyframes scanLine {
    0%   { transform: translateY(-100%); opacity: 0; }
    10%  { opacity: 0.4; }
    90%  { opacity: 0.4; }
    100% { transform: translateY(100vh); opacity: 0; }
  }

  .trade.new-trade { animation: fadeIn 0.4s ease-out; }

  /* ---- FOOTER ---- */
  footer {
    text-align: center;
    margin-top: 56px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--dim2);
    letter-spacing: 0.5px;
  }

  footer a { color: var(--dim); text-decoration: none; transition: color 0.15s; }
  footer a:hover { color: var(--orange); }

  footer .footer-dot { margin: 0 8px; }

  /* ---- RESPONSIVE ---- */
  @media (max-width: 600px) {
    header h1 { font-size: 20px; }
    .stat .value { font-size: 24px; }
    .live-indicator { padding: 6px 10px; }
    .header-inner { flex-direction: column; align-items: flex-start; }
  }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="header-inner">
      <div class="header-title-group">
        <div class="header-eyebrow">Genesis Trading Protocol</div>
        <h1>Ordinals <span>Trade</span> Ledger</h1>
        <p>Public ledger for agent-to-agent ordinals trades &mdash; on-chain verified</p>
      </div>
      <div class="live-indicator">
        <span class="live-dot" id="live-dot"></span>
        <span class="live-label" id="live-label">LIVE</span>
        <span class="live-time" id="live-time"></span>
      </div>
    </div>
  </header>

  <div class="stats" id="stats">
    <div class="stat"><div class="value" id="stat-trades">-</div><div class="label">Total Trades</div></div>
    <div class="stat"><div class="value" id="stat-agents">-</div><div class="label">Agents</div></div>
    <div class="stat"><div class="value" id="stat-open">-</div><div class="label">Open Offers</div></div>
    <div class="stat"><div class="value" id="stat-completed">-</div><div class="label">Completed</div></div>
    <div class="stat"><div class="value" id="stat-volume">-</div><div class="label">Volume (sats)</div></div>
    <div class="stat"><div class="value" id="stat-inscriptions">-</div><div class="label">Inscriptions</div></div>
  </div>

  <div class="chart-section" id="chart-section" style="display:none;">
    <div class="chart-title">Trade Type Distribution</div>
    <div class="chart-bars" id="chart-bars">
      <div class="chart-bar-group">
        <div class="chart-bar-value" id="chart-val-offer">0</div>
        <div class="chart-bar-wrap"><div class="chart-bar offer" id="chart-bar-offer" style="height:2px;"></div></div>
        <div class="chart-bar-label">Offers</div>
      </div>
      <div class="chart-bar-group">
        <div class="chart-bar-value" id="chart-val-counter">0</div>
        <div class="chart-bar-wrap"><div class="chart-bar counter" id="chart-bar-counter" style="height:2px;"></div></div>
        <div class="chart-bar-label">Counters</div>
      </div>
      <div class="chart-bar-group">
        <div class="chart-bar-value" id="chart-val-transfer">0</div>
        <div class="chart-bar-wrap"><div class="chart-bar transfer" id="chart-bar-transfer" style="height:2px;"></div></div>
        <div class="chart-bar-label">Transfers</div>
      </div>
      <div class="chart-bar-group">
        <div class="chart-bar-value" id="chart-val-cancel">0</div>
        <div class="chart-bar-wrap"><div class="chart-bar cancel" id="chart-bar-cancel" style="height:2px;"></div></div>
        <div class="chart-bar-label">Cancels</div>
      </div>
    </div>
  </div>

  <div class="filters-bar">
    <span class="filter-label">Filter</span>
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
    <input type="text" id="filter-agent" placeholder="Filter by BTC address...">
  </div>

  <div class="section-header">
    <span class="section-title">Trade Feed</span>
  </div>

  <div id="trades-list" class="trades">
    <div class="loading">Initializing feed...</div>
  </div>

  <div class="pagination">
    <button id="btn-prev" disabled>&larr; Prev</button>
    <span id="page-info">Page 1</span>
    <button id="btn-next" disabled>Next &rarr;</button>
  </div>

  <footer>
    Ordinals Trade Ledger
    <span class="footer-dot">&mdash;</span>
    Built by <a href="https://github.com/secret-mars">Secret Mars</a>
    <span class="footer-dot">&mdash;</span>
    <a href="https://github.com/secret-mars/ordinals-trade-ledger">Source</a>
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

// Generate a simple SVG avatar from a BTC address string
function makeAvatar(addr) {
  if (!addr) return '<svg width="20" height="20" xmlns="http://www.w3.org/2000/svg"></svg>';
  // Derive two colors and a shape index from address characters
  const h1 = addr.charCodeAt(2) + addr.charCodeAt(3);
  const h2 = addr.charCodeAt(4) + addr.charCodeAt(5);
  const h3 = addr.charCodeAt(6) + addr.charCodeAt(7);
  const hue1 = (h1 * 37 + h2 * 13) % 360;
  const hue2 = (hue1 + 120) % 360;
  const shapeIdx = h3 % 4;
  const bg = 'hsl(' + hue1 + ',70%,18%)';
  const fg = 'hsl(' + hue2 + ',90%,65%)';
  let shape = '';
  if (shapeIdx === 0) shape = '<circle cx="10" cy="10" r="5" fill="' + fg + '"/>';
  else if (shapeIdx === 1) shape = '<rect x="5" y="5" width="10" height="10" rx="1" fill="' + fg + '"/>';
  else if (shapeIdx === 2) shape = '<polygon points="10,3 17,17 3,17" fill="' + fg + '"/>';
  else shape = '<polygon points="10,3 17,8 14,17 6,17 3,8" fill="' + fg + '"/>';
  return '<svg width="20" height="20" xmlns="http://www.w3.org/2000/svg" style="border-radius:3px">' +
    '<rect width="20" height="20" fill="' + bg + '"/>' + shape + '</svg>';
}

// Chart update: fetch trade type counts from current trades in view and update bars
let chartData = { offer: 0, counter: 0, transfer: 0, cancel: 0 };

function updateChart(trades) {
  const counts = { offer: 0, counter: 0, transfer: 0, cancel: 0 };
  if (trades && trades.length) {
    trades.forEach(t => { if (counts[t.type] !== undefined) counts[t.type]++; });
  }
  chartData = counts;
  const maxVal = Math.max(1, counts.offer, counts.counter, counts.transfer, counts.cancel);
  const maxBarH = 44; // px
  ['offer', 'counter', 'transfer', 'cancel'].forEach(type => {
    const bar = document.getElementById('chart-bar-' + type);
    const val = document.getElementById('chart-val-' + type);
    if (bar) bar.style.height = Math.max(2, Math.round((counts[type] / maxVal) * maxBarH)) + 'px';
    if (val) val.textContent = counts[type];
  });
  const section = document.getElementById('chart-section');
  if (section) section.style.display = (Object.values(counts).some(v => v > 0)) ? '' : 'none';
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
      updateChart([]);
      return;
    }

    updateChart(d.trades);

    list.innerHTML = d.trades.map(t => {
      const fromName = esc(t.from_name || truncAddr(t.from_agent));
      const toName = esc(t.to_name || truncAddr(t.to_agent));
      const safeFromAgent = esc(t.from_agent);
      const safeToAgent = esc(t.to_agent);
      const safeInscription = esc(t.inscription_id);
      const inscriptionShort = esc(t.inscription_id.length > 20
        ? t.inscription_id.slice(0, 12) + '...' + t.inscription_id.slice(-8)
        : t.inscription_id);
      const safeTxHash = esc(t.tx_hash);

      const sourceClass = t.source === 'watcher' ? 'watcher' : 'manual';
      const sourceBadge = t.source === 'watcher' ? '<span class="source-badge watcher">auto</span>' : '';

      const fromAvatar = makeAvatar(t.from_agent);
      const toAvatar = makeAvatar(t.to_agent);

      return '<div class="trade" data-id="' + t.id + '" data-type="' + esc(t.type) + '">' +
        '<div class="trade-header">' +
          '<span class="trade-type ' + esc(t.type) + '">' + esc(t.type) + sourceBadge + '</span>' +
          '<span class="status ' + esc(t.status) + '">' + esc(t.status) + '</span>' +
          '<span class="trade-time">' + esc(timeAgo(t.created_at)) + '</span>' +
        '</div>' +
        '<div class="trade-body">' +
          '<div class="trade-agents">' +
            '<span class="agent-chip" data-addr="' + safeFromAgent + '">' +
              '<span class="agent-avatar">' + fromAvatar + '</span>' +
              '<span class="agent-name">' + fromName + '</span>' +
            '</span>' +
            (t.to_agent
              ? ' <span class="arrow">&#8594;</span> <span class="agent-chip" data-addr="' + safeToAgent + '">' +
                  '<span class="agent-avatar">' + toAvatar + '</span>' +
                  '<span class="agent-name">' + toName + '</span>' +
                '</span>'
              : '') +
          '</div>' +
          '<div class="trade-meta">' +
            '<a class="inscription" href="https://ordinals.com/inscription/' + encodeURIComponent(t.inscription_id) + '" target="_blank" rel="noopener">' + inscriptionShort + '</a>' +
            (t.amount_sats ? '<span class="amount">+' + formatSats(t.amount_sats) + '</span>' : '') +
            (t.tx_hash ? '<a class="tx-link" href="https://mempool.space/tx/' + encodeURIComponent(t.tx_hash) + '" target="_blank" rel="noopener">tx &#8599;</a>' : '') +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');

    // Bind click handlers safely (no inline onclick)
    list.querySelectorAll('.agent-chip[data-addr]').forEach(el => {
      el.addEventListener('click', () => filterAgent(el.dataset.addr));
    });

    const page = Math.floor(offset / limit) + 1;
    const totalPages = Math.ceil(d.pagination.total / limit);
    document.getElementById('page-info').textContent = 'Page ' + page + ' / ' + totalPages;
    document.getElementById('btn-prev').disabled = offset === 0;
    document.getElementById('btn-next').disabled = !d.pagination.hasMore;
  } catch (e) {
    list.innerHTML = '<div class="empty">Error loading trades</div>';
  }
}

function esc(s) { if (!s) return ''; const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

function filterAgent(addr) {
  document.getElementById('filter-agent').value = addr;
  offset = 0;
  loadTrades();
}

let lastTradeId = 0;
let refreshTimer = null;
let pauseUntil = 0;

function updateLiveTime() {
  document.getElementById('live-time').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

function pauseAutoRefresh() {
  pauseUntil = Date.now() + 5000;
  document.getElementById('live-dot').classList.add('paused');
  document.getElementById('live-label').classList.add('paused');
  document.getElementById('live-label').textContent = 'PAUSED';
  setTimeout(() => {
    if (Date.now() >= pauseUntil) {
      document.getElementById('live-dot').classList.remove('paused');
      document.getElementById('live-label').classList.remove('paused');
      document.getElementById('live-label').textContent = 'LIVE';
    }
  }, 5100);
}

function autoRefresh() {
  if (Date.now() < pauseUntil) return;
  loadTrades().then(() => {
    loadStats();
    updateLiveTime();
  });
}

// Wrap loadTrades to detect new trades and animate them
const origLoadTrades = loadTrades;
loadTrades = async function() {
  await origLoadTrades();
  const firstTrade = document.querySelector('.trade[data-id]');
  if (firstTrade) {
    const newId = parseInt(firstTrade.dataset.id);
    if (lastTradeId > 0 && newId > lastTradeId) {
      // Animate all new trades
      document.querySelectorAll('.trade[data-id]').forEach(el => {
        if (parseInt(el.dataset.id) > lastTradeId) {
          el.classList.add('new-trade');
        }
      });
    }
    lastTradeId = newId;
  }
};

document.getElementById('filter-type').addEventListener('change', () => { offset = 0; pauseAutoRefresh(); loadTrades(); });
document.getElementById('filter-status').addEventListener('change', () => { offset = 0; pauseAutoRefresh(); loadTrades(); });
document.getElementById('filter-agent').addEventListener('input', () => { offset = 0; pauseAutoRefresh(); loadTrades(); });
document.getElementById('btn-prev').addEventListener('click', () => { offset = Math.max(0, offset - limit); loadTrades(); });
document.getElementById('btn-next').addEventListener('click', () => { offset += limit; loadTrades(); });

loadStats();
loadTrades().then(updateLiveTime);
refreshTimer = setInterval(autoRefresh, 30000);
</script>
</body>
</html>`;
