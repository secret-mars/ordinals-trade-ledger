-- Migration 007: Normalize legacy source values in trades table
-- Trades 1-5 had `source` set to timestamp strings (e.g. "2026-02-17 04:38:37")
-- instead of valid enum values ("watcher", "manual", "api").
-- This migration corrects those rows by mapping timestamp-like source values to "manual".

UPDATE trades SET source = 'manual' WHERE source LIKE '20%-%-%';
