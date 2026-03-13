-- Migration 007: Fix legacy trades with malformed source values
-- Trades 1-5 were inserted before source validation was added and have
-- timestamp strings (e.g., "2026-02-17 04:38:37") instead of valid enum
-- values. This migration normalises them to 'manual' (the default).

UPDATE trades
SET source = 'manual',
    updated_at = datetime('now')
WHERE id <= 5
  AND source NOT IN ('watcher', 'manual', 'api');
