-- Migration 005: IP-based rate limiting for write endpoints
-- Tracks request counts per IP per endpoint per 5-minute sliding window.
-- Write endpoints (POST, PUT, PATCH, DELETE) are limited to 10 requests
-- per IP per endpoint per window. Expired windows are cleaned up lazily
-- on each rate-limited request and by the scheduled cron handler.

CREATE TABLE IF NOT EXISTS rate_limits (
  ip TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  window_start TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (ip, endpoint, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
