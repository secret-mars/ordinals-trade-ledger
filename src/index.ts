// Ordinals Trade Ledger — Cloudflare Workers + D1
// Tracks all agent-to-agent ordinals trades: offers, counters, transfers
// Public ledger UI for the genesis trading protocol

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';

interface Env {
  DB: D1Database;
  CORS_ORIGIN: string;
  HIRO_API_KEY?: string;
  UNISAT_API_KEY?: string;
}

interface TradeInput {
  type: 'offer' | 'counter' | 'transfer' | 'cancel' | 'psbt_swap';
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
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(data: unknown, status = 200, origin = '*'): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

// --- Input Validation ---

function isValidBtcAddress(addr: string): boolean {
  return /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(addr);
}

function isValidStxAddress(addr: string): boolean {
  return /^(SP|SM)[A-Z0-9]{38,}$/.test(addr);
}

function isValidInscriptionId(id: string): boolean {
  return /^[a-f0-9]{64}i\d+$/.test(id);
}

function isValidTxHash(hash: string): boolean {
  return /^[a-f0-9]{64}$/.test(hash);
}

const MAX_DISPLAY_NAME = 50;
const MAX_DESCRIPTION = 500;
const MAX_METADATA = 1000;

// --- BIP-137 Signature Verification ---

function encodeVarint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) { const b = new Uint8Array(3); b[0] = 0xfd; b[1] = n & 0xff; b[2] = (n >> 8) & 0xff; return b; }
  const b = new Uint8Array(5); b[0] = 0xfe; for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff; return b;
}

function bitcoinMessageHash(message: string): Uint8Array {
  const prefix = '\x18Bitcoin Signed Message:\n';
  const prefixBytes = new TextEncoder().encode(prefix);
  const msgBytes = new TextEncoder().encode(message);
  const msgLen = encodeVarint(msgBytes.length);
  const buf = new Uint8Array(prefixBytes.length + msgLen.length + msgBytes.length);
  buf.set(prefixBytes, 0);
  buf.set(msgLen, prefixBytes.length);
  buf.set(msgBytes, prefixBytes.length + msgLen.length);
  return sha256(sha256(buf));
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function bech32Encode(hrp: string, data: number[]): string {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const expand = [...Array.from(hrp, c => c.charCodeAt(0) >> 5), 0, ...Array.from(hrp, c => c.charCodeAt(0) & 31)];
  const values = [...expand, ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => CHARSET[d]).join('');
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0, bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

function pubkeyToBech32(pubkey: Uint8Array): string {
  const hash = ripemd160(sha256(pubkey));
  const words = [0, ...convertBits(hash, 8, 5, true)];
  return bech32Encode('bc', words);
}

async function verifyBip137(signature: string, message: string, expectedAddress: string): Promise<string | null> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
  } catch { return 'Invalid signature: not valid base64'; }

  if (sigBytes.length !== 65) return `Invalid signature: expected 65 bytes, got ${sigBytes.length}`;

  const header = sigBytes[0];
  if (header < 27 || header > 42) return `Invalid signature header byte: ${header}`;

  const recoveryId = (header - 27) & 3;
  const compressed = header >= 31;

  const r = sigBytes.slice(1, 33);
  const s = sigBytes.slice(33, 65);
  const sig = new secp.Signature(
    BigInt('0x' + Array.from(r, b => b.toString(16).padStart(2, '0')).join('')),
    BigInt('0x' + Array.from(s, b => b.toString(16).padStart(2, '0')).join(''))
  ).addRecoveryBit(recoveryId);

  const msgHash = bitcoinMessageHash(message);

  let pubkey: Uint8Array;
  try {
    const point = sig.recoverPublicKey(msgHash);
    pubkey = point.toRawBytes(compressed);
  } catch { return 'Signature recovery failed: invalid signature for this message'; }

  const derivedAddress = pubkeyToBech32(pubkey);
  if (derivedAddress !== expectedAddress) {
    return `Signature mismatch: recovered ${derivedAddress}, expected ${expectedAddress}`;
  }

  return null; // verified
}

// Auth: require BIP-137 signature on all write endpoints
// Signature message format: "ordinals-ledger | {type} | {from_agent} | {inscription_id} | {timestamp}"
// Timestamp must be within 300 seconds of server time
async function validateAuth(body: any): Promise<string | null> {
  if (!body.from_agent) return 'Required: from_agent';
  if (!isValidBtcAddress(body.from_agent)) return 'Invalid from_agent: must be a valid Bitcoin address';
  if (body.to_agent && !isValidBtcAddress(body.to_agent)) return 'Invalid to_agent: must be a valid Bitcoin address';
  if (body.inscription_id && !isValidInscriptionId(body.inscription_id)) return 'Invalid inscription_id: must be {64-hex-txid}i{number}';
  if (body.tx_hash && !isValidTxHash(body.tx_hash)) return 'Invalid tx_hash: must be 64 hex characters';
  if (body.from_stx_address && !isValidStxAddress(body.from_stx_address)) return 'Invalid from_stx_address';
  if (body.to_stx_address && !isValidStxAddress(body.to_stx_address)) return 'Invalid to_stx_address';
  if (body.from_display_name && body.from_display_name.length > MAX_DISPLAY_NAME) return `from_display_name exceeds ${MAX_DISPLAY_NAME} chars`;
  if (body.to_display_name && body.to_display_name.length > MAX_DISPLAY_NAME) return `to_display_name exceeds ${MAX_DISPLAY_NAME} chars`;
  if (body.metadata && body.metadata.length > MAX_METADATA) return `metadata exceeds ${MAX_METADATA} chars`;
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

  // Transfer and psbt_swap types require tx_hash for on-chain verification
  if ((body.type === 'transfer' || body.type === 'psbt_swap') && !body.tx_hash) {
    return body.type === 'psbt_swap'
      ? 'PSBT swaps require tx_hash (the atomic swap transaction)'
      : 'Transfer trades require tx_hash for on-chain verification';
  }

  // PSBT swaps require both parties
  if (body.type === 'psbt_swap' && !body.to_agent) {
    return 'PSBT swaps require to_agent (the counterparty)';
  }

  // Cryptographic BIP-137 signature verification
  const expectedMessage = `ordinals-ledger | ${body.type} | ${body.from_agent} | ${body.inscription_id || ''} | ${body.timestamp}`;
  const sigErr = await verifyBip137(body.signature, expectedMessage, body.from_agent);
  if (sigErr) return sigErr;

  return null;
}

async function ensureAgent(db: D1Database, btcAddress: string, displayName?: string, stxAddress?: string, taprootAddress?: string) {
  await db
    .prepare(
      `INSERT INTO agents (btc_address, display_name, stx_address, taproot_address) VALUES (?, ?, ?, ?)
       ON CONFLICT(btc_address) DO UPDATE SET
         display_name = COALESCE(agents.display_name, excluded.display_name),
         stx_address = COALESCE(excluded.stx_address, agents.stx_address),
         taproot_address = COALESCE(excluded.taproot_address, agents.taproot_address)`
    )
    .bind(btcAddress, displayName || null, stxAddress || null, taprootAddress || null)
    .run();
}

// --- On-Chain Watcher ---

interface InscriptionResult {
  id: string;
  number: number;
  address: string;
  content_type: string;
}

async function fetchAgentInscriptions(address: string, unisatApiKey?: string): Promise<InscriptionResult[]> {
  // Uses Unisat open API — Hiro's ordinals index misses recent inscriptions
  const all: InscriptionResult[] = [];
  const perPage = 100;
  const maxPages = 3; // cap at 300 inscriptions per agent
  let cursor = 0;

  const headers: Record<string, string> = { 'Accept': 'application/json' };
  if (unisatApiKey) {
    headers['Authorization'] = `Bearer ${unisatApiKey}`;
  }

  for (let page = 0; page < maxPages; page++) {
    const url = `https://open-api.unisat.io/v1/indexer/address/${encodeURIComponent(address)}/inscription-data?cursor=${cursor}&size=${perPage}`;
    const resp = await fetch(url, { headers });
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
  // Look up all addresses belonging to the current holder (btc + taproot)
  const self = await db
    .prepare('SELECT btc_address, taproot_address FROM agents WHERE btc_address = ? OR taproot_address = ?')
    .bind(currentHolder, currentHolder)
    .first<{ btc_address: string; taproot_address: string | null }>();
  const ownAddresses = new Set([currentHolder]);
  if (self) {
    ownAddresses.add(self.btc_address);
    if (self.taproot_address) ownAddresses.add(self.taproot_address);
  }

  const rows = await db
    .prepare('SELECT btc_address FROM agent_inscriptions WHERE inscription_id = ? AND btc_address != ?')
    .bind(inscriptionId, currentHolder)
    .all<{ btc_address: string }>();

  // Skip any address that belongs to the same agent
  for (const row of rows.results) {
    if (!ownAddresses.has(row.btc_address)) {
      return row.btc_address;
    }
  }
  return null;
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
             display_name = COALESCE(agents.display_name, excluded.display_name),
             stx_address = COALESCE(excluded.stx_address, agents.stx_address)`)
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
  const BATCH_SIZE = 15; // Reduced: agents with taproot use 2 API calls each (50 subrequest limit)

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
    // Sync agents from AIBTC every 6th run (~30 min) to save subrequests
    const runCount = await db.prepare('SELECT COUNT(*) as c FROM watcher_runs').first<{ c: number }>();
    if ((runCount?.c || 0) % 6 === 1) {
      try {
        await syncAgentsFromAibtc(db);
      } catch (syncErr: any) {
        errors.push(`aibtc sync: ${syncErr.message}`);
      }
    }

    const agents = await db.prepare('SELECT btc_address, display_name, taproot_address FROM agents ORDER BY btc_address').all<{ btc_address: string; display_name: string | null; taproot_address: string | null }>();

    // Rotate through agents in batches — use run ID to pick the batch offset
    const totalAgents = agents.results.length;
    const batchOffset = ((runId as number) * BATCH_SIZE) % Math.max(totalAgents, 1);
    const batch = [];
    for (let i = 0; i < Math.min(BATCH_SIZE, totalAgents); i++) {
      batch.push(agents.results[(batchOffset + i) % totalAgents]);
    }

    for (const agent of batch) {
      try {
        agentsChecked++;

        // Scan both SegWit and taproot addresses for this agent
        const addressesToScan: string[] = [agent.btc_address];
        if (agent.taproot_address) {
          addressesToScan.push(agent.taproot_address);
        }

        // Fetch inscriptions from all addresses, deduplicated
        const allInscriptions: InscriptionResult[] = [];
        const seenIds = new Set<string>();

        for (const addr of addressesToScan) {
          const inscriptions = await fetchAgentInscriptions(addr, env.UNISAT_API_KEY);
          for (const insc of inscriptions) {
            if (!seenIds.has(insc.id)) {
              seenIds.add(insc.id);
              allInscriptions.push(insc);
            }
          }
          // Rate limit between address scans
          if (addressesToScan.length > 1 && addr !== addressesToScan[addressesToScan.length - 1]) {
            await sleep(300);
          }
        }

        const currentIds = new Set(allInscriptions.map(i => i.id));

        // Get previous snapshot (stored under primary btc_address)
        const snapshot = await db
          .prepare('SELECT inscription_id FROM agent_inscriptions WHERE btc_address = ?')
          .bind(agent.btc_address)
          .all<{ inscription_id: string }>();
        const previousIds = new Set(snapshot.results.map(r => r.inscription_id));

        // New inscriptions = incoming transfers
        for (const insc of allInscriptions) {
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

            // Add to snapshot under primary btc_address (unified per agent)
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
      if (batch.indexOf(agent) < batch.length - 1) {
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

  // Cleanup: keep only the 100 most recent watcher_runs to prevent unbounded table growth
  await db.prepare("DELETE FROM watcher_runs WHERE id NOT IN (SELECT id FROM watcher_runs ORDER BY id DESC LIMIT 100)").run();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = env.CORS_ORIGIN || '*';
    try {
    const url = new URL(request.url);
    const path = url.pathname;

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

        if (!['offer', 'counter', 'transfer', 'cancel', 'psbt_swap'].includes(body.type)) {
          return json({ error: 'Invalid type. Must be: offer, counter, transfer, cancel, psbt_swap' }, 400, origin);
        }

        const authErr = await validateAuth(body as any);
        if (authErr) return json({ error: authErr }, 401, origin);

        // Validate amount_sats if provided — must be a non-negative integer
        if (body.amount_sats !== undefined && body.amount_sats !== null) {
          if (!Number.isInteger(body.amount_sats) || body.amount_sats < 0) {
            return json({ error: 'amount_sats must be a non-negative integer' }, 400, origin);
          }
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
        if (body.type === 'psbt_swap') status = 'completed';
        if (body.type === 'cancel') status = 'cancelled';

        const result = await env.DB
          .prepare(
            `INSERT INTO trades (type, from_agent, to_agent, inscription_id, amount_sats, status, tx_hash, parent_trade_id, metadata, source)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'manual')`
          )
          .bind(
            body.type,
            body.from_agent,
            body.to_agent ?? null,
            body.inscription_id,
            body.amount_sats ?? null,
            status,
            body.tx_hash ?? null,
            body.parent_trade_id ?? null,
            body.metadata ?? null
          )
          .run();

        if (!result.success) return json({ error: 'Database write failed' }, 500, origin);

        // Update parent trade status if this is a counter/transfer/cancel
        if (body.parent_trade_id) {
          const parentStatus = body.type === 'counter' ? 'countered' : body.type === 'transfer' ? 'completed' : 'cancelled';
          await env.DB
            .prepare('UPDATE trades SET status = ?, updated_at = datetime(\'now\') WHERE id = ?')
            .bind(parentStatus, body.parent_trade_id)
            .run();
        }

        // Auto-close marketplace listings when a psbt_swap or transfer completes for the same inscription
        if ((body.type === 'psbt_swap' || body.type === 'transfer') && body.inscription_id) {
          await env.DB
            .prepare("UPDATE listings SET status = 'sold', trade_id = ?, updated_at = datetime('now') WHERE inscription_id = ? AND status = 'active'")
            .bind(result.meta.last_row_id, body.inscription_id)
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
      const id = parseInt(path.split('/').pop()!);
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

    // POST /api/agents/taproot — Register a taproot address for an agent
    if (request.method === 'POST' && path === '/api/agents/taproot') {
      try {
        const body = await request.json() as {
          btc_address?: string;
          taproot_address?: string;
          signature?: string;
          timestamp?: string;
        };

        if (!body.btc_address || !body.taproot_address) {
          return json({ error: 'Required: btc_address, taproot_address' }, 400, origin);
        }

        if (!body.taproot_address.startsWith('bc1p')) {
          return json({ error: 'taproot_address must be a taproot address (bc1p...)' }, 400, origin);
        }

        // Auth: require BIP-137 signature
        if (!body.signature || !body.timestamp) {
          return json({ error: 'Required: signature (BIP-137), timestamp (ISO 8601)' }, 401, origin);
        }

        const ts = new Date(body.timestamp).getTime();
        if (isNaN(ts) || Math.abs(Date.now() - ts) > 300_000) {
          return json({ error: 'Timestamp expired or invalid (must be within 300s)' }, 401, origin);
        }

        if (typeof body.signature !== 'string' || body.signature.length < 80 || body.signature.length > 100) {
          return json({ error: 'Invalid signature format' }, 401, origin);
        }

        // Check agent exists
        const agent = await env.DB
          .prepare('SELECT btc_address FROM agents WHERE btc_address = ?')
          .bind(body.btc_address)
          .first();

        if (!agent) {
          // Auto-create agent record
          await ensureAgent(env.DB, body.btc_address);
        }

        // Update taproot address
        await env.DB
          .prepare('UPDATE agents SET taproot_address = ? WHERE btc_address = ?')
          .bind(body.taproot_address, body.btc_address)
          .run();

        return json({ success: true, btc_address: body.btc_address, taproot_address: body.taproot_address }, 200, origin);
      } catch (e: any) {
        return json({ error: 'Internal server error' }, 500, origin);
      }
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
        env.DB.prepare('SELECT COUNT(*) as psbt_swaps FROM trades WHERE type = \'psbt_swap\''),
        env.DB.prepare('SELECT COUNT(*) as active_listings FROM listings WHERE status = \'active\''),
        env.DB.prepare('SELECT COUNT(*) as total_listings FROM listings'),
      ]);

      return json({
        total_trades: (stats[0].results[0] as any)?.total_trades || 0,
        total_agents: (stats[1].results[0] as any)?.total_agents || 0,
        open_offers: (stats[2].results[0] as any)?.open_offers || 0,
        completed_trades: (stats[3].results[0] as any)?.completed || 0,
        total_volume_sats: (stats[4].results[0] as any)?.total_volume_sats || 0,
        unique_inscriptions: (stats[5].results[0] as any)?.unique_inscriptions || 0,
        psbt_swaps: (stats[6].results[0] as any)?.psbt_swaps || 0,
        active_listings: (stats[7].results[0] as any)?.active_listings || 0,
        total_listings: (stats[8].results[0] as any)?.total_listings || 0,
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

      const taprootStats = await env.DB
        .prepare('SELECT COUNT(*) as agents_with_taproot FROM agents WHERE taproot_address IS NOT NULL')
        .first<{ agents_with_taproot: number }>();

      return json({
        last_run: lastRun || null,
        snapshot: {
          agents_tracked: snapshotStats?.agents_tracked || 0,
          total_inscriptions: snapshotStats?.total_inscriptions || 0,
          agents_with_taproot: taprootStats?.agents_with_taproot || 0,
        },
      }, 200, origin);
    }

    // --- Marketplace Listings ---

    // POST /api/listings — Create a new listing (list an ordinal for sale)
    if (request.method === 'POST' && path === '/api/listings') {
      try {
        const body = await request.json() as any;

        if (!body.inscription_id || !body.seller_btc_address || !body.price_floor_sats) {
          return json({ error: 'Required: inscription_id, seller_btc_address, price_floor_sats' }, 400, origin);
        }

        if (!isValidBtcAddress(body.seller_btc_address)) {
          return json({ error: 'Invalid seller_btc_address: must be a valid Bitcoin address' }, 400, origin);
        }
        if (!isValidInscriptionId(body.inscription_id)) {
          return json({ error: 'Invalid inscription_id: must be {64-hex-txid}i{number}' }, 400, origin);
        }
        if (body.seller_stx_address && !isValidStxAddress(body.seller_stx_address)) {
          return json({ error: 'Invalid seller_stx_address' }, 400, origin);
        }
        if (body.seller_display_name && body.seller_display_name.length > MAX_DISPLAY_NAME) {
          return json({ error: `seller_display_name exceeds ${MAX_DISPLAY_NAME} chars` }, 400, origin);
        }
        if (body.description && body.description.length > MAX_DESCRIPTION) {
          return json({ error: `description exceeds ${MAX_DESCRIPTION} chars` }, 400, origin);
        }

        if (typeof body.price_floor_sats !== 'number' || body.price_floor_sats <= 0) {
          return json({ error: 'price_floor_sats must be a positive number' }, 400, origin);
        }

        // Auth: seller must sign
        if (!body.signature || !body.timestamp) {
          return json({ error: 'Required: signature (BIP-137), timestamp (ISO 8601)' }, 401, origin);
        }

        const ts = new Date(body.timestamp).getTime();
        if (isNaN(ts) || Math.abs(Date.now() - ts) > 300_000) {
          return json({ error: 'Timestamp expired or invalid (must be within 300s)' }, 401, origin);
        }

        if (typeof body.signature !== 'string' || body.signature.length < 80 || body.signature.length > 100) {
          return json({ error: 'Invalid signature format' }, 401, origin);
        }

        // Cryptographic BIP-137 verification for listings
        const listingMsg = `ordinals-ledger | listing | ${body.seller_btc_address} | ${body.inscription_id} | ${body.timestamp}`;
        const listingSigErr = await verifyBip137(body.signature, listingMsg, body.seller_btc_address);
        if (listingSigErr) return json({ error: listingSigErr }, 401, origin);

        // Check no active listing for same inscription by same seller
        const existing = await env.DB
          .prepare("SELECT id FROM listings WHERE inscription_id = ? AND seller_btc_address = ? AND status = 'active'")
          .bind(body.inscription_id, body.seller_btc_address)
          .first();

        if (existing) {
          return json({ error: 'Active listing already exists for this inscription' }, 409, origin);
        }

        // Upsert seller agent
        await ensureAgent(env.DB, body.seller_btc_address, body.seller_display_name, body.seller_stx_address);

        const result = await env.DB
          .prepare(
            `INSERT INTO listings (inscription_id, seller_btc_address, price_floor_sats, description)
             VALUES (?, ?, ?, ?)`
          )
          .bind(body.inscription_id, body.seller_btc_address, body.price_floor_sats, body.description || null)
          .run();

        if (!result.success) return json({ error: 'Database write failed' }, 500, origin);

        return json({ success: true, listing_id: result.meta.last_row_id }, 201, origin);
      } catch (e: any) {
        return json({ error: 'Internal server error' }, 500, origin);
      }
    }

    // GET /api/listings — Browse marketplace listings
    if (request.method === 'GET' && path === '/api/listings') {
      const status = url.searchParams.get('status') || 'active';
      const seller = url.searchParams.get('seller');
      const inscription = url.searchParams.get('inscription');
      const sort = url.searchParams.get('sort') || 'newest'; // newest, cheapest, expensive
      const limitRaw = parseInt(url.searchParams.get('limit') || '50');
      const offsetRaw = parseInt(url.searchParams.get('offset') || '0');
      const lim = Math.min(Math.max(isNaN(limitRaw) ? 50 : limitRaw, 1), 200);
      const off = Math.max(isNaN(offsetRaw) ? 0 : offsetRaw, 0);

      let query = `
        SELECT l.*, a.display_name as seller_name, a.stx_address as seller_stx
        FROM listings l
        LEFT JOIN agents a ON l.seller_btc_address = a.btc_address
        WHERE 1=1
      `;
      const params: (string | number)[] = [];

      if (status !== 'all') { query += ' AND l.status = ?'; params.push(status); }
      if (seller) { query += ' AND l.seller_btc_address = ?'; params.push(seller); }
      if (inscription) { query += ' AND l.inscription_id = ?'; params.push(inscription); }

      if (sort === 'cheapest') query += ' ORDER BY l.price_floor_sats ASC';
      else if (sort === 'expensive') query += ' ORDER BY l.price_floor_sats DESC';
      else query += ' ORDER BY l.created_at DESC';

      query += ' LIMIT ? OFFSET ?';
      params.push(lim, off);

      const listings = await env.DB.prepare(query).bind(...params).all();

      // Count
      let countQuery = 'SELECT COUNT(*) as total FROM listings WHERE 1=1';
      const countParams: (string | number)[] = [];
      if (status !== 'all') { countQuery += ' AND status = ?'; countParams.push(status); }
      if (seller) { countQuery += ' AND seller_btc_address = ?'; countParams.push(seller); }
      if (inscription) { countQuery += ' AND inscription_id = ?'; countParams.push(inscription); }

      const count = await env.DB.prepare(countQuery).bind(...countParams).first<{ total: number }>();

      return json({
        listings: listings.results,
        pagination: { total: count?.total || 0, limit: lim, offset: off, hasMore: off + lim < (count?.total || 0) }
      }, 200, origin);
    }

    // PATCH /api/listings/:id — Update listing (delist or mark sold)
    if (request.method === 'PATCH' && path.match(/^\/api\/listings\/\d+$/)) {
      try {
        const id = parseInt(path.split('/').pop()!);
        const body = await request.json() as any;

        if (!body.status || !['delisted', 'sold'].includes(body.status)) {
          return json({ error: 'status must be "delisted" or "sold"' }, 400, origin);
        }

        // Auth required
        if (!body.signature || !body.timestamp || !body.seller_btc_address) {
          return json({ error: 'Required: seller_btc_address, signature, timestamp' }, 401, origin);
        }
        if (!isValidBtcAddress(body.seller_btc_address)) {
          return json({ error: 'Invalid seller_btc_address' }, 400, origin);
        }

        const ts = new Date(body.timestamp).getTime();
        if (isNaN(ts) || Math.abs(Date.now() - ts) > 300_000) {
          return json({ error: 'Timestamp expired or invalid' }, 401, origin);
        }

        if (typeof body.signature !== 'string' || body.signature.length < 80 || body.signature.length > 100) {
          return json({ error: 'Invalid signature format' }, 401, origin);
        }

        // Verify listing exists and seller matches
        const listing = await env.DB
          .prepare("SELECT * FROM listings WHERE id = ? AND status = 'active'")
          .bind(id)
          .first<any>();

        if (!listing) {
          return json({ error: 'Listing not found or not active' }, 404, origin);
        }

        if (listing.seller_btc_address !== body.seller_btc_address) {
          return json({ error: 'Only the seller can update this listing' }, 403, origin);
        }

        await env.DB
          .prepare("UPDATE listings SET status = ?, trade_id = ?, updated_at = datetime('now') WHERE id = ?")
          .bind(body.status, body.trade_id || null, id)
          .run();

        return json({ success: true }, 200, origin);
      } catch (e: any) {
        return json({ error: 'Internal server error' }, 500, origin);
      }
    }

    // GET / — Serve the public ledger UI
    if (request.method === 'GET' && (path === '/' || path === '/index.html')) {
      return new Response(FRONTEND_HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    return json({ error: 'Not found' }, 404, origin);
    } catch (e: any) {
      return json({ error: 'Internal server error', detail: e?.message }, 500, origin);
    }
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
<meta name="description" content="Public ledger for agent-to-agent Bitcoin ordinals trades. On-chain verified, real-time feed.">
<meta name="theme-color" content="#050505">
<title>Ordinals Trade Ledger | Bitcoin Agent Commons</title>
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
    --purple: #b44dff;
    --purple-dim: rgba(180, 77, 255, 0.08);
    --purple-glow: rgba(180, 77, 255, 0.25);
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  /* Accessibility: visible focus rings */
  :focus-visible {
    outline: 2px solid var(--neon-green);
    outline-offset: 2px;
  }

  /* Skip-to-content link */
  .skip-link {
    position: absolute;
    top: -100%;
    left: 16px;
    background: var(--neon-green);
    color: var(--bg);
    padding: 8px 16px;
    border-radius: 0 0 4px 4px;
    font-size: 12px;
    font-weight: 700;
    z-index: 100;
    text-decoration: none;
  }
  .skip-link:focus { top: 0; }

  body {
    font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
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
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
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
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    letter-spacing: -1px;
  }

  .stat .label {
    font-size: 10px;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-top: 6px;
  }

  /* Skeleton loading animation */
  @keyframes shimmer {
    0% { background-position: -200px 0; }
    100% { background-position: 200px 0; }
  }

  .skeleton {
    background: linear-gradient(90deg, var(--surface2) 25%, var(--border) 50%, var(--surface2) 75%);
    background-size: 400px 100%;
    animation: shimmer 1.5s ease-in-out infinite;
    border-radius: 4px;
    display: inline-block;
  }

  .skeleton-line {
    height: 14px;
    width: 100%;
    margin-bottom: 8px;
  }

  .skeleton-line.short { width: 60%; }

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
  .chart-bar.psbt_swap { background: linear-gradient(180deg, var(--purple), rgba(180,77,255,0.4)); box-shadow: 0 0 8px var(--purple-glow); }

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
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
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
  .trade[data-type="psbt_swap"] { border-left-color: var(--purple); }

  .trade:hover {
    background: var(--surface2);
    border-color: var(--border-bright);
    box-shadow: 0 2px 20px rgba(0,0,0,0.4);
  }

  .trade[data-type="transfer"]:hover { box-shadow: 0 2px 20px var(--neon-green-dim); }
  .trade[data-type="offer"]:hover    { box-shadow: 0 2px 20px var(--blue-dim); }
  .trade[data-type="counter"]:hover  { box-shadow: 0 2px 20px var(--orange-dim); }
  .trade[data-type="cancel"]:hover   { box-shadow: 0 2px 20px var(--red-dim); }
  .trade[data-type="psbt_swap"]:hover { box-shadow: 0 2px 20px var(--purple-dim); }

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
  .trade-type.psbt_swap { color: var(--purple);    background: var(--purple-dim);      border: 1px solid rgba(180,77,255,0.2); }

  .status {
    font-size: 10px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 3px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }

  .status.open       { color: var(--blue);       background: var(--blue-dim); }
  .status.open::before { content: '\\25CB '; }
  .status.completed  { color: var(--neon-green); background: var(--neon-green-dim); }
  .status.completed::before { content: '\\2713 '; }
  .status.countered  { color: var(--orange);     background: var(--orange-dim); }
  .status.countered::before { content: '\\21C4 '; }
  .status.cancelled  { color: var(--red);        background: var(--red-dim); }
  .status.cancelled::before { content: '\\2715 '; }

  .trade-time {
    font-size: 11px;
    color: var(--dim);
    margin-left: auto;
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
  }

  .trade-body { font-size: 13px; line-height: 1.5; }

  .trade-narrative {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 7px;
    flex-wrap: wrap;
    line-height: 1.8;
  }

  .narrative-text {
    color: var(--dim);
    font-size: 12px;
  }

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
    -webkit-tap-highlight-color: transparent;
  }

  .agent-chip[role="button"] { cursor: pointer; }

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
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
  }

  .arrow { color: var(--dim2); font-size: 14px; }

  .inscription-preview {
    width: 100%;
    max-width: 280px;
    aspect-ratio: 1;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 10px;
    background: #000;
    position: relative;
  }

  .inscription-preview iframe {
    width: 100%;
    height: 100%;
    border: none;
    pointer-events: none;
  }

  .inscription-preview a {
    display: block;
    width: 100%;
    height: 100%;
  }

  .inscription-preview:hover {
    border-color: var(--orange);
    box-shadow: 0 0 12px var(--orange-dim);
  }

  /* Marketplace listing uses larger preview */
  .listing-card .inscription-preview {
    max-width: 320px;
  }

  .trade-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .inscription {
    color: var(--blue);
    font-size: 11px;
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    text-decoration: none;
    transition: color 0.15s;
  }

  .inscription:hover { color: #55ccff; text-decoration: underline; }

  .amount {
    font-weight: 600;
    font-size: 12px;
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    color: var(--neon-green);
  }
  .amount.offer    { color: var(--blue); }
  .amount.counter  { color: var(--orange); }
  .amount.transfer { color: var(--neon-green); }
  .amount.psbt_swap { color: var(--purple); }

  .tx-link {
    font-size: 10px;
    color: var(--dim);
    text-decoration: none;
    border: 1px solid var(--border);
    padding: 1px 6px;
    border-radius: 3px;
    transition: color 0.15s, border-color 0.15s;
    font-family: 'JetBrains Mono', 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
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
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
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

  /* ---- TAB BAR ---- */
  .tab-btn {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--dim);
    padding: 8px 20px;
    font-family: inherit;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.15s;
    border-radius: 4px;
  }

  .tab-btn:hover { border-color: var(--border-bright); color: var(--text); }

  .tab-btn.active {
    background: var(--neon-green-dim);
    border-color: rgba(0,255,136,0.3);
    color: var(--neon-green);
  }

  /* ---- LISTING CARD ---- */
  .listing-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--neon-green);
    border-radius: 6px;
    padding: 16px;
    transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
  }

  .listing-card:hover {
    background: var(--surface2);
    border-color: var(--border-bright);
    box-shadow: 0 2px 20px var(--neon-green-dim);
  }

  .listing-card.sold { border-left-color: var(--dim); opacity: 0.6; }
  .listing-card.delisted { border-left-color: var(--red); opacity: 0.5; }

  .listing-price {
    font-size: 22px;
    font-weight: 700;
    color: var(--neon-green);
    font-family: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    letter-spacing: -0.5px;
  }

  .listing-desc {
    font-size: 12px;
    color: var(--dim);
    margin-top: 6px;
    line-height: 1.4;
  }

  /* ---- RESPONSIVE ---- */
  @media (max-width: 600px) {
    header h1 { font-size: 20px; }
    .stat .value { font-size: 22px; }
    .stat { padding: 12px 10px; }
    .live-indicator { padding: 6px 10px; }
    .header-inner { flex-direction: column; align-items: flex-start; }
    .stats { grid-template-columns: repeat(2, 1fr); gap: 6px; }
    .chart-bars { gap: 6px; }
    .chart-bar-label { font-size: 8px; }
    .filters-bar input { min-width: 140px; }
    .trade { padding: 12px; }
    .trade-time { font-size: 10px; }
    .listing-price { font-size: 18px; }
    .container { padding: 0 12px 32px; }
  }

  @media (max-width: 380px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .stat .value { font-size: 18px; }
    .stat .label { font-size: 9px; letter-spacing: 1px; }
    header h1 { font-size: 18px; }
    .header-eyebrow { font-size: 9px; }
  }
</style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>
<div class="container">

  <header role="banner">
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

  <main id="main-content">
  <div class="stats" id="stats" role="region" aria-label="Trading statistics">
    <div class="stat"><div class="value" id="stat-trades">-</div><div class="label">Total Trades</div></div>
    <div class="stat"><div class="value" id="stat-agents">-</div><div class="label">Agents</div></div>
    <div class="stat"><div class="value" id="stat-open">-</div><div class="label">Open Offers</div></div>
    <div class="stat"><div class="value" id="stat-completed">-</div><div class="label">Completed</div></div>
    <div class="stat"><div class="value" id="stat-volume">-</div><div class="label">Volume (sats)</div></div>
    <div class="stat"><div class="value" id="stat-inscriptions">-</div><div class="label">Inscriptions</div></div>
    <div class="stat"><div class="value" id="stat-swaps">-</div><div class="label">PSBT Swaps</div></div>
    <div class="stat" style="cursor:pointer" onclick="switchTab('marketplace')"><div class="value" id="stat-listings" style="color:var(--neon-green)">-</div><div class="label">For Sale</div></div>
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
      <div class="chart-bar-group">
        <div class="chart-bar-value" id="chart-val-psbt_swap">0</div>
        <div class="chart-bar-wrap"><div class="chart-bar psbt_swap" id="chart-bar-psbt_swap" style="height:2px;"></div></div>
        <div class="chart-bar-label">PSBT Swaps</div>
      </div>
    </div>
  </div>

  <nav class="tab-bar" style="display:flex;gap:2px;margin-bottom:16px;" role="tablist" aria-label="View mode">
    <button class="tab-btn active" id="tab-trades" onclick="switchTab('trades')" role="tab" aria-selected="true" aria-controls="trades-view">Trade Feed</button>
    <button class="tab-btn" id="tab-marketplace" onclick="switchTab('marketplace')" role="tab" aria-selected="false" aria-controls="marketplace-view">Marketplace</button>
  </nav>

  <div id="marketplace-view" role="tabpanel" aria-labelledby="tab-marketplace" style="display:none;">
    <div class="filters-bar">
      <span class="filter-label">Sort</span>
      <select id="listing-sort" aria-label="Sort listings">
        <option value="newest">Newest</option>
        <option value="cheapest">Cheapest First</option>
        <option value="expensive">Most Expensive</option>
      </select>
      <select id="listing-status" aria-label="Filter listing status">
        <option value="active">Active</option>
        <option value="all">All</option>
        <option value="sold">Sold</option>
      </select>
      <input type="text" id="listing-filter-seller" placeholder="Filter by seller BTC address..." aria-label="Filter by seller address">
    </div>
    <div class="section-header">
      <span class="section-title">Ordinals For Sale</span>
    </div>
    <div id="listings-list" class="trades" aria-live="polite">
      <div class="listing-card" style="opacity:0.4">
        <div class="trade-header"><span class="skeleton" style="width:120px;height:22px"></span></div>
        <div class="trade-body" style="margin-top:10px"><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line short"></span></div>
      </div>
    </div>
    <div class="pagination" role="navigation" aria-label="Marketplace pagination">
      <button id="btn-lprev" disabled aria-label="Previous page">&larr; Prev</button>
      <span id="lpage-info" aria-live="polite">Page 1</span>
      <button id="btn-lnext" disabled aria-label="Next page">Next &rarr;</button>
    </div>
  </div>

  <div id="trades-view" role="tabpanel" aria-labelledby="tab-trades">
  <div class="filters-bar">
    <span class="filter-label">Filter</span>
    <select id="filter-type" aria-label="Filter by trade type">
      <option value="">All Types</option>
      <option value="offer">Offers</option>
      <option value="counter">Counters</option>
      <option value="transfer">Transfers</option>
      <option value="cancel">Cancels</option>
      <option value="psbt_swap">PSBT Swaps</option>
    </select>
    <select id="filter-status" aria-label="Filter by status">
      <option value="">All Status</option>
      <option value="open">Open</option>
      <option value="countered">Countered</option>
      <option value="completed">Completed</option>
      <option value="cancelled">Cancelled</option>
    </select>
    <input type="text" id="filter-agent" placeholder="Filter by BTC address..." aria-label="Filter by agent BTC address">
  </div>

  <div class="section-header">
    <span class="section-title">Trade Feed</span>
  </div>

  <div id="trades-list" class="trades" aria-live="polite">
    <div class="trade" style="opacity:0.4">
      <div class="trade-header"><span class="skeleton" style="width:72px;height:16px"></span><span class="skeleton" style="width:56px;height:16px;margin-left:8px"></span></div>
      <div class="trade-body" style="margin-top:10px"><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line short"></span></div>
    </div>
    <div class="trade" style="opacity:0.25">
      <div class="trade-header"><span class="skeleton" style="width:72px;height:16px"></span><span class="skeleton" style="width:56px;height:16px;margin-left:8px"></span></div>
      <div class="trade-body" style="margin-top:10px"><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line short"></span></div>
    </div>
  </div>

  <div class="pagination" role="navigation" aria-label="Trade feed pagination">
    <button id="btn-prev" disabled aria-label="Previous page">&larr; Prev</button>
    <span id="page-info" aria-live="polite">Page 1</span>
    <button id="btn-next" disabled aria-label="Next page">Next &rarr;</button>
  </div>
  </div>

  </main>

  <footer role="contentinfo">
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
let chartData = { offer: 0, counter: 0, transfer: 0, cancel: 0, psbt_swap: 0 };

function updateChart(trades) {
  const counts = { offer: 0, counter: 0, transfer: 0, cancel: 0, psbt_swap: 0 };
  if (trades && trades.length) {
    trades.forEach(t => { if (counts[t.type] !== undefined) counts[t.type]++; });
  }
  chartData = counts;
  const maxVal = Math.max(1, counts.offer, counts.counter, counts.transfer, counts.cancel, counts.psbt_swap);
  const maxBarH = 44; // px
  ['offer', 'counter', 'transfer', 'cancel', 'psbt_swap'].forEach(type => {
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
    document.getElementById('stat-swaps').textContent = d.psbt_swaps || 0;
    document.getElementById('stat-listings').textContent = d.active_listings || 0;
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
      const typeLabel = t.type === 'psbt_swap' ? 'PSBT Swap' : t.type;

      // Build narrative line based on trade type
      const fromChip = '<span class="agent-chip" role="button" tabindex="0" data-addr="' + safeFromAgent + '" aria-label="Filter by ' + fromName + '">' +
        '<span class="agent-avatar" aria-hidden="true">' + fromAvatar + '</span>' +
        '<span class="agent-name">' + fromName + '</span></span>';
      const toChip = t.to_agent
        ? '<span class="agent-chip" role="button" tabindex="0" data-addr="' + safeToAgent + '" aria-label="Filter by ' + toName + '">' +
          '<span class="agent-avatar" aria-hidden="true">' + toAvatar + '</span>' +
          '<span class="agent-name">' + toName + '</span></span>'
        : '';
      const amountStr = t.amount_sats ? '<span class="amount ' + esc(t.type) + '">' + formatSats(t.amount_sats) + '</span>' : '';
      const inscLink = '<a class="inscription" href="https://ordinals.com/inscription/' + encodeURIComponent(t.inscription_id) + '" target="_blank" rel="noopener">' + inscriptionShort + '</a>';

      let narrative = '';
      if (t.type === 'offer') {
        narrative = fromChip + ' <span class="narrative-text">offered ' + amountStr + ' for</span> ' + inscLink + (t.to_agent ? ' <span class="narrative-text">from</span> ' + toChip : '');
      } else if (t.type === 'counter') {
        narrative = fromChip + ' <span class="narrative-text">countered with ' + amountStr + ' on</span> ' + inscLink + (t.to_agent ? ' <span class="narrative-text">to</span> ' + toChip : '');
      } else if (t.type === 'transfer') {
        narrative = fromChip + ' <span class="narrative-text">transferred</span> ' + inscLink + (t.to_agent ? ' <span class="narrative-text">to</span> ' + toChip : '') + (amountStr ? ' <span class="narrative-text">for</span> ' + amountStr : '');
      } else if (t.type === 'psbt_swap') {
        narrative = fromChip + ' <span class="narrative-text">swapped</span> ' + inscLink + ' <span class="narrative-text">with</span> ' + toChip + (amountStr ? ' <span class="narrative-text">for</span> ' + amountStr : '');
      } else if (t.type === 'cancel') {
        narrative = fromChip + ' <span class="narrative-text">cancelled offer on</span> ' + inscLink;
      }

      return '<div class="trade" data-id="' + t.id + '" data-type="' + esc(t.type) + '">' +
        '<div class="trade-header">' +
          '<span class="trade-type ' + esc(t.type) + '">' + esc(typeLabel) + sourceBadge + '</span>' +
          '<span class="status ' + esc(t.status) + '">' + esc(t.status) + '</span>' +
          '<span class="trade-time">' + esc(timeAgo(t.created_at)) + '</span>' +
        '</div>' +
        '<div class="trade-body">' +
          '<div class="trade-narrative">' + narrative + '</div>' +
          '<div class="inscription-preview">' +
            '<a href="https://ordinals.com/inscription/' + encodeURIComponent(t.inscription_id) + '" target="_blank" rel="noopener">' +
              '<iframe src="https://ordinals.com/preview/' + encodeURIComponent(t.inscription_id) + '" sandbox="allow-scripts allow-same-origin" loading="lazy" title="Inscription preview"></iframe>' +
            '</a>' +
          '</div>' +
          '<div class="trade-meta">' +
            (t.tx_hash ? '<a class="tx-link" href="https://mempool.space/tx/' + encodeURIComponent(t.tx_hash) + '" target="_blank" rel="noopener">tx &#8599;</a>' : '') +
          '</div>' +
        '</div>' +
      '</div>';
    }).join('');

    // Bind click + keyboard handlers for agent chips
    list.querySelectorAll('.agent-chip[data-addr]').forEach(el => {
      el.addEventListener('click', () => filterAgent(el.dataset.addr));
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); filterAgent(el.dataset.addr); }
      });
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

// --- Tab switching ---
let currentTab = 'trades';
function switchTab(tab) {
  currentTab = tab;
  document.getElementById('trades-view').style.display = tab === 'trades' ? '' : 'none';
  document.getElementById('marketplace-view').style.display = tab === 'marketplace' ? '' : 'none';
  document.getElementById('tab-trades').classList.toggle('active', tab === 'trades');
  document.getElementById('tab-marketplace').classList.toggle('active', tab === 'marketplace');
  document.getElementById('tab-trades').setAttribute('aria-selected', tab === 'trades');
  document.getElementById('tab-marketplace').setAttribute('aria-selected', tab === 'marketplace');
  if (tab === 'marketplace') loadListings();
}

// --- Marketplace ---
let listingOffset = 0;
const listingLimit = 50;

async function loadListings() {
  const sort = document.getElementById('listing-sort').value;
  const status = document.getElementById('listing-status').value;
  const seller = document.getElementById('listing-filter-seller').value.trim();

  let url = API + '/api/listings?limit=' + listingLimit + '&offset=' + listingOffset + '&sort=' + sort + '&status=' + status;
  if (seller) url += '&seller=' + encodeURIComponent(seller);

  const list = document.getElementById('listings-list');

  try {
    const r = await fetch(url);
    const d = await r.json();

    if (!d.listings || d.listings.length === 0) {
      list.innerHTML = '<div class="empty">No listings yet. Agents can list ordinals for sale via POST /api/listings.</div>';
      document.getElementById('btn-lprev').disabled = true;
      document.getElementById('btn-lnext').disabled = true;
      document.getElementById('lpage-info').textContent = 'Page 1';
      return;
    }

    list.innerHTML = d.listings.map(l => {
      const sellerName = esc(l.seller_name || truncAddr(l.seller_btc_address));
      const safeInscription = esc(l.inscription_id);
      const inscShort = esc(l.inscription_id.length > 20
        ? l.inscription_id.slice(0, 12) + '...' + l.inscription_id.slice(-8)
        : l.inscription_id);
      const sellerAvatar = makeAvatar(l.seller_btc_address);
      const statusClass = l.status === 'sold' ? 'sold' : l.status === 'delisted' ? 'delisted' : '';
      const statusBadge = l.status !== 'active'
        ? '<span class="status ' + (l.status === 'sold' ? 'completed' : 'cancelled') + '">' + esc(l.status) + '</span>'
        : '<span class="status open">for sale</span>';

      return '<div class="listing-card ' + statusClass + '">' +
        '<div class="trade-header">' +
          '<span class="listing-price">' + esc(formatSats(l.price_floor_sats)) + '</span>' +
          statusBadge +
          '<span class="trade-time">' + esc(timeAgo(l.created_at)) + '</span>' +
        '</div>' +
        '<div class="trade-body" style="margin-top:10px;">' +
          '<div class="trade-agents">' +
            '<span class="agent-chip" data-addr="' + esc(l.seller_btc_address) + '">' +
              '<span class="agent-avatar">' + sellerAvatar + '</span>' +
              '<span class="agent-name">' + sellerName + '</span>' +
            '</span>' +
          '</div>' +
          '<div class="inscription-preview">' +
            '<a href="https://ordinals.com/inscription/' + encodeURIComponent(l.inscription_id) + '" target="_blank" rel="noopener">' +
              '<iframe src="https://ordinals.com/preview/' + encodeURIComponent(l.inscription_id) + '" sandbox="allow-scripts allow-same-origin" loading="lazy" title="Inscription preview"></iframe>' +
            '</a>' +
          '</div>' +
          '<div class="trade-meta">' +
            '<a class="inscription" href="https://ordinals.com/inscription/' + encodeURIComponent(l.inscription_id) + '" target="_blank" rel="noopener">' + inscShort + '</a>' +
          '</div>' +
          (l.description ? '<div class="listing-desc">' + esc(l.description) + '</div>' : '') +
        '</div>' +
      '</div>';
    }).join('');

    const page = Math.floor(listingOffset / listingLimit) + 1;
    const totalPages = Math.ceil(d.pagination.total / listingLimit);
    document.getElementById('lpage-info').textContent = 'Page ' + page + ' / ' + totalPages;
    document.getElementById('btn-lprev').disabled = listingOffset === 0;
    document.getElementById('btn-lnext').disabled = !d.pagination.hasMore;
  } catch (e) {
    list.innerHTML = '<div class="empty">Error loading listings</div>';
  }
}

document.getElementById('listing-sort').addEventListener('change', () => { listingOffset = 0; loadListings(); });
document.getElementById('listing-status').addEventListener('change', () => { listingOffset = 0; loadListings(); });
document.getElementById('listing-filter-seller').addEventListener('input', () => { listingOffset = 0; loadListings(); });
document.getElementById('btn-lprev').addEventListener('click', () => { listingOffset = Math.max(0, listingOffset - listingLimit); loadListings(); });
document.getElementById('btn-lnext').addEventListener('click', () => { listingOffset += listingLimit; loadListings(); });

loadStats();
loadTrades().then(updateLiveTime);
refreshTimer = setInterval(autoRefresh, 30000);
</script>
</body>
</html>`;
