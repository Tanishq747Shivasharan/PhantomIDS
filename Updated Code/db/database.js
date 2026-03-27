const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const dbPath = path.join(__dirname, 'phantom.db');
const db = new Database(dbPath);

// Enable WAL mode for high-speed concurrent writes (handles sqlmap ~147 req/14s)
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = 10000');
db.pragma('temp_store = MEMORY');

// --- BAIT TABLE: vulnerable users (intentionally weak, for honeypot) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'employee'
  )
`);

// Seed bait users if empty
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const insertUser = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
  insertUser.run('admin', 'admin123', 'admin');
  insertUser.run('john.doe', 'password1', 'employee');
  insertUser.run('jane.smith', 'letmein', 'employee');
  insertUser.run('root', 'toor', 'superuser');
}

// --- ADMINS TABLE: secure admin accounts for the dashboard ---
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    org TEXT NOT NULL
  )
`);

const adminCount = db.prepare('SELECT COUNT(*) as count FROM admins').get();
if (adminCount.count === 0) {
  // bcryptjs hash of 'PhantomAdmin@2024'
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync('PhantomAdmin@2024', 10);
  db.prepare('INSERT INTO admins (username, password, org) VALUES (?, ?, ?)').run('phantom_admin', hash, 'PhantomIDS Security');
}

// --- ATTACK LOG TABLE ---
db.exec(`
  CREATE TABLE IF NOT EXISTS attack_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    method TEXT,
    path TEXT,
    payload TEXT,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'NORMAL'
  )
`);

// --- IP TRACKER TABLE (for ML 3-Strikes logic) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS ip_tracker (
    ip TEXT PRIMARY KEY,
    request_count INTEGER DEFAULT 0,
    window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'NORMAL',
    threat_count INTEGER DEFAULT 0
  )
`);

// Add threat_count column if upgrading from older schema
try {
  db.exec(`ALTER TABLE ip_tracker ADD COLUMN threat_count INTEGER DEFAULT 0`);
} catch (_) { /* column already exists — safe to ignore */ }

// Indexes for performance
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_attack_log_ip ON attack_log(ip);
  CREATE INDEX IF NOT EXISTS idx_attack_log_timestamp ON attack_log(timestamp);
  CREATE INDEX IF NOT EXISTS idx_attack_log_status ON attack_log(status);
`);

module.exports = db;
