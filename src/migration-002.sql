-- Migration 002: Add psbt_swap trade type for atomic ordinals swaps
-- SQLite doesn't support ALTER CHECK, so recreate the trades table

CREATE TABLE trades_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK (type IN ('offer', 'counter', 'transfer', 'cancel', 'psbt_swap')),
  from_agent TEXT NOT NULL,
  to_agent TEXT,
  inscription_id TEXT NOT NULL,
  amount_sats INTEGER,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'countered', 'accepted', 'completed', 'cancelled')),
  tx_hash TEXT,
  parent_trade_id INTEGER REFERENCES trades_new(id),
  metadata TEXT,
  source TEXT DEFAULT 'manual',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (from_agent) REFERENCES agents(btc_address),
  FOREIGN KEY (to_agent) REFERENCES agents(btc_address)
);

INSERT INTO trades_new SELECT * FROM trades;
DROP TABLE trades;
ALTER TABLE trades_new RENAME TO trades;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_trades_type ON trades(type);
CREATE INDEX IF NOT EXISTS idx_trades_from ON trades(from_agent);
CREATE INDEX IF NOT EXISTS idx_trades_to ON trades(to_agent);
CREATE INDEX IF NOT EXISTS idx_trades_inscription ON trades(inscription_id);
CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
CREATE INDEX IF NOT EXISTS idx_trades_created ON trades(created_at DESC);
