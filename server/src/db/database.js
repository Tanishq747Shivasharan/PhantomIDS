'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

const dbDir = path.join(__dirname);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(path.join(__dirname, 'phantom.db'));

db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = 10000');
db.pragma('temp_store = MEMORY');

// Honeypot bait users — intentionally weak credentials for sqlmap to dump
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role     TEXT DEFAULT 'employee'
  )
`);

const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const insert = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
  insert.run('admin',      'admin123',   'admin');
  insert.run('john.doe',   'password1',  'employee');
  insert.run('jane.smith', 'letmein',    'employee');
  insert.run('root',       'toor',       'superuser');
}

// Secure admin accounts for the dashboard (bcrypt-hashed)
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    org      TEXT NOT NULL
  )
`);

const adminCount = db.prepare('SELECT COUNT(*) as count FROM admins').get();
if (adminCount.count === 0) {
  const bcrypt = require('bcryptjs');
  const hash   = bcrypt.hashSync('PhantomAdmin@2024', 10);
  db.prepare('INSERT INTO admins (username, password, org) VALUES (?, ?, ?)').run('phantom_admin', hash, 'PhantomIDS Security');
}

db.exec(`
  CREATE TABLE IF NOT EXISTS attack_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    method     TEXT,
    path       TEXT,
    payload    TEXT,
    user_agent TEXT,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    status     TEXT DEFAULT 'NORMAL'
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS ip_tracker (
    ip            TEXT PRIMARY KEY,
    request_count INTEGER DEFAULT 0,
    window_start  DATETIME DEFAULT CURRENT_TIMESTAMP,
    status        TEXT DEFAULT 'NORMAL',
    threat_count  INTEGER DEFAULT 0
  )
`);

// Safe migration for older schemas missing threat_count
try {
  db.exec('ALTER TABLE ip_tracker ADD COLUMN threat_count INTEGER DEFAULT 0');
} catch (_) {}

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_attack_log_ip        ON attack_log(ip);
  CREATE INDEX IF NOT EXISTS idx_attack_log_timestamp ON attack_log(timestamp);
  CREATE INDEX IF NOT EXISTS idx_attack_log_status    ON attack_log(status);
`);

module.exports = db;
