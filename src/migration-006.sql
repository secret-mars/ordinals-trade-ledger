-- Migration 006: Add taproot_address column to agents table
-- Enables agents to register a P2TR (bc1p...) address alongside their SegWit
-- address for inscription scanning and taproot-native asset tracking.

ALTER TABLE agents ADD COLUMN taproot_address TEXT;
