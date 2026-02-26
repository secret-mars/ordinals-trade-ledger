-- Migration 004: Signature replay protection
-- Stores a hash of each accepted BIP-137 signature to prevent replay attacks.
-- Signatures are rejected if the same signature is submitted more than once
-- within 24 hours. Expired entries (older than 24h) are cleaned up lazily on
-- each trade submission and by the scheduled watcher cron.

CREATE TABLE IF NOT EXISTS used_signatures (
  sig_hash TEXT PRIMARY KEY,
  used_at TEXT NOT NULL DEFAULT (datetime('now'))
);
