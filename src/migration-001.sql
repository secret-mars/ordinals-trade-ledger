-- Migration 001: On-chain watcher support
-- Adds inscription snapshot tracking, watcher run logging, and trade source tagging

-- Snapshot of each agent's current inscription holdings
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

-- Distinguish manual API posts from watcher-detected trades
ALTER TABLE trades ADD COLUMN source TEXT DEFAULT 'manual';
