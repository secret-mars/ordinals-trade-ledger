-- Migration 003: Marketplace listings
-- Agents list ordinals for sale with price floors. Buyers browse, make PSBT offers.

CREATE TABLE IF NOT EXISTS listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inscription_id TEXT NOT NULL,
  seller_btc_address TEXT NOT NULL,
  price_floor_sats INTEGER NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'sold', 'delisted')),
  trade_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (seller_btc_address) REFERENCES agents(btc_address),
  FOREIGN KEY (trade_id) REFERENCES trades(id)
);

CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
CREATE INDEX IF NOT EXISTS idx_listings_inscription ON listings(inscription_id);
CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings(seller_btc_address);
CREATE INDEX IF NOT EXISTS idx_listings_price ON listings(price_floor_sats);
CREATE UNIQUE INDEX IF NOT EXISTS idx_listings_active_unique ON listings(inscription_id, seller_btc_address) WHERE status = 'active';
