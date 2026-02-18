-- Ordinals Trade Ledger — D1 Schema
-- Tracks all agent-to-agent ordinals trades: offers, counters, transfers

CREATE TABLE IF NOT EXISTS agents (
  btc_address TEXT PRIMARY KEY,
  stx_address TEXT,
  display_name TEXT,
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  trade_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS trades (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK (type IN ('offer', 'counter', 'transfer', 'cancel', 'psbt_swap')),
  from_agent TEXT NOT NULL,
  to_agent TEXT,
  inscription_id TEXT NOT NULL,
  amount_sats INTEGER,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'countered', 'accepted', 'completed', 'cancelled')),
  tx_hash TEXT,
  parent_trade_id INTEGER REFERENCES trades(id),
  metadata TEXT,
  source TEXT DEFAULT 'manual',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (from_agent) REFERENCES agents(btc_address),
  FOREIGN KEY (to_agent) REFERENCES agents(btc_address)
);

-- Snapshot of each agent's current inscription holdings (for on-chain watcher)
CREATE TABLE IF NOT EXISTS agent_inscriptions (
  btc_address TEXT NOT NULL,
  inscription_id TEXT NOT NULL,
  first_seen TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (btc_address, inscription_id),
  FOREIGN KEY (btc_address) REFERENCES agents(btc_address)
);

-- Log of each watcher cron run for observability
CREATE TABLE IF NOT EXISTS watcher_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'error')),
  agents_checked INTEGER NOT NULL DEFAULT 0,
  transfers_found INTEGER NOT NULL DEFAULT 0,
  errors TEXT
);

CREATE INDEX IF NOT EXISTS idx_trades_type ON trades(type);
CREATE INDEX IF NOT EXISTS idx_trades_from ON trades(from_agent);
CREATE INDEX IF NOT EXISTS idx_trades_to ON trades(to_agent);
CREATE INDEX IF NOT EXISTS idx_trades_inscription ON trades(inscription_id);
CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
CREATE INDEX IF NOT EXISTS idx_trades_created ON trades(created_at DESC);
