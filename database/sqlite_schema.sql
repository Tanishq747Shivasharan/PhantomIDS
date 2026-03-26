-- PhantomIDS: Local SQLite Schema

-- ====================================================================
-- This file exists for reference. The actual table creation is triggered
-- within honeypot_project/honeypot.py via the init_db() function upon start.
-- ====================================================================

-- Existing tables:
-- `users` (id, username, password, role)
-- `attack_log` (id, timestamp, attacker, username, password, user_agent, result)

-- ====================================================================
-- New tables for Cloud Sync (Tracking Alerts destined for Supabase)
-- ====================================================================

CREATE TABLE IF NOT EXISTS local_alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    attacker   TEXT,
    timestamp  TEXT,
    payload    TEXT,
    score      INTEGER,
    synced     INTEGER DEFAULT 0 -- 0 = Unsynced, 1 = Synced
);

-- ====================================================================
-- New table for Cloud Sync (Tracking IP Reputations locally)
-- ====================================================================

CREATE TABLE IF NOT EXISTS local_threat_ips (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT UNIQUE,
    attack_count INTEGER DEFAULT 1,
    first_seen   TEXT,
    last_seen    TEXT,
    synced       INTEGER DEFAULT 0 -- 0 = Unsynced, 1 = Synced
);

-- Note: WAL mode (Write-Ahead Log) is strongly recommended for thread-safety 
-- as the main Flask app writes locally, and a background thread
-- reads `synced = 0` to push to Supabase REST APIs.
