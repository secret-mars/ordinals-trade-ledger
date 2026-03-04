-- Migration 007: Normalize legacy trade source values
-- Trades 1-5 were inserted before field validation; their source column
-- contains raw timestamps (e.g. "2026-02-17 04:38:37") instead of valid
-- enum values. This migration corrects them to 'manual' and adds a CHECK
-- constraint to prevent future bad data.
-- Closes #62

-- Step 1: Fix malformed source values (timestamps) -> 'manual'
UPDATE trades
  SET source = 'manual',
      updated_at = datetime('now')
  WHERE source NOT IN ('watcher', 'manual', 'api');

-- Step 2: Recreate the trades table with a CHECK constraint on source.
-- D1/SQLite does not support ALTER TABLE ... ADD CONSTRAINT, so we use
-- the standard rename-copy-drop pattern.

-- 2a. Rename old table
ALTER TABLE trades RENAME TO trades_old;

-- 2b. Create new table with CHECK constraint on source
CREATE TABLE trades (
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
  source TEXT DEFAULT 'manual' CHECK (source IN ('watcher', 'manual', 'api')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (from_agent) REFERENCES agents(btc_address),
  FOREIGN KEY (to_agent) REFERENCES agents(btc_address)
);

-- 2c. Copy all rows (source values already normalized in Step 1)
INSERT INTO trades
  SELECT * FROM trades_old;

-- 2d. Drop the old table
DROP TABLE trades_old;

-- 2e. Re-create indexes (dropped with the old table)
CREATE INDEX IF NOT EXISTS idx_trades_type ON trades(type);
CREATE INDEX IF NOT EXISTS idx_trades_from ON trades(from_agent);
CREATE INDEX IF NOT EXISTS idx_trades_to ON trades(to_agent);
CREATE INDEX IF NOT EXISTS idx_trades_inscription ON trades(inscription_id);
CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
CREATE INDEX IF NOT EXISTS idx_trades_created ON trades(created_at DESC);
