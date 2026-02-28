-- Migration 006: Add taproot_address column to agents table (#53)
-- Required by POST /api/agents/taproot and the watcher cron
ALTER TABLE agents ADD COLUMN taproot_address TEXT;
