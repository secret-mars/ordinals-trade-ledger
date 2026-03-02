-- Migration 006: Add taproot address support for agents
-- Enables /api/agents/taproot and watcher dual-address scanning.

ALTER TABLE agents ADD COLUMN taproot_address TEXT;
