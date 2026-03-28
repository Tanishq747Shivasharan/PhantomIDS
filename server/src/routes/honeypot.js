const express = require('express');
const router = express.Router();
const db = require('../db/database');

// ============================================================
// INTENTIONALLY VULNERABLE HONEYPOT LOGIN
// Purpose: Attract and log SQL injection attacks from sqlmap
// WARNING: This is deliberately insecure by design.
// ============================================================

function logAttack(req, payload) {
  // Prefer X-Forwarded-For set by ESP32 (real attacker IP)
  const ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const method = req.method;
  const urlPath = req.originalUrl;

  // Determine status from threat detector
  const status = req.ipStatus || (() => {
    const tracker = db.prepare('SELECT status FROM ip_tracker WHERE ip = ?').get(ip);
    return tracker ? tracker.status : 'NORMAL';
  })();

  try {
    db.prepare(`
      INSERT INTO attack_log (ip, method, path, payload, user_agent, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(ip, method, urlPath, payload, userAgent, status);
  } catch (err) {
    console.error('[Honeypot] DB log error:', err.message);
  }
}

// POST /login — INTENTIONALLY VULNERABLE SQL INJECTION ENDPOINT
router.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // Capture full payload for logging
  const payload = `username=${username}&password=${password}`;
  logAttack(req, payload);

  // ⚠️  DELIBERATE SQL INJECTION VULNERABILITY — DO NOT SANITIZE
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;

  let result = null;
  let sqlError = null;

  try {
    result = db.prepare(query).get();
  } catch (err) {
    sqlError = err.message;
    // Log the SQL error payload too — valuable for IDS
    console.log(`[Honeypot] SQL Error from ${req.ip}: ${err.message}`);
  }

  // Return realistic responses to keep sqlmap probing
  if (sqlError) {
    // Return a plausible server error (not a 500 that kills sqlmap)
    return res.status(200).json({
      success: false,
      message: 'An internal error occurred. Please try again.',
      debug: sqlError   // intentional "accidental" debug leak — bait
    });
  }

  if (result) {
    return res.status(200).json({
      success: true,
      message: `Welcome back, ${result.username}!`,
      role: result.role,
      redirect: '/employee-portal'
    });
  }

  return res.status(200).json({
    success: false,
    message: 'Invalid username or password.'
  });
});

// GET /honeypot-status — for admin to verify honeypot is live
router.get('/honeypot-status', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as total FROM attack_log').get();
  res.json({ status: 'ACTIVE', total_attacks_logged: count.total });
});

// ============================================================
// POST /api/esp32/alert — ESP32 hardware sensor alert ingest
// ESP32 POSTs here when it detects a confirmed SQLi (score >= 2):
//   { "attacker_ip": "192.168.1.7", "payload": "...", "score": 2 }
// ============================================================
router.post('/api/esp32/alert', (req, res) => {
  const { attacker_ip, payload, score } = req.body;

  if (!attacker_ip) {
    return res.status(400).json({ error: 'attacker_ip is required' });
  }

  const ip       = attacker_ip;
  const severity = score >= 2 ? 'BANNED' : 'THREAT';

  try {
    // The forwarded request already created a row with the real attacker IP.
    // Update the most recent row from this IP within the last 5 seconds.
    const updated = db.prepare(`
      UPDATE attack_log
      SET status = ?
      WHERE id = (
        SELECT id FROM attack_log
        WHERE ip = ?
        AND timestamp >= datetime('now', '-5 seconds')
        ORDER BY id DESC
        LIMIT 1
      )
    `).run(severity, ip);

    // If no existing row (direct ESP32 alert with no forwarded request), insert one
    if (updated.changes === 0) {
      db.prepare(`
        INSERT INTO attack_log (ip, method, path, payload, user_agent, status)
        VALUES (?, 'POST', '/login', ?, 'ESP32-PhantomIDS/1.0', ?)
      `).run(ip, payload || '', severity);
    }

    // Upsert ip_tracker
    const existing = db.prepare('SELECT * FROM ip_tracker WHERE ip = ?').get(ip);
    if (existing) {
      db.prepare(`
        UPDATE ip_tracker
        SET threat_count = threat_count + 1,
            status = CASE WHEN status != 'BANNED' THEN ? ELSE 'BANNED' END
        WHERE ip = ?
      `).run(severity, ip);
    } else {
      db.prepare(`
        INSERT INTO ip_tracker (ip, request_count, window_start, status, threat_count)
        VALUES (?, 1, datetime('now'), ?, 1)
      `).run(ip, severity);
    }

    lastEsp32Ping = Date.now();

    console.log(`[ESP32] ${score >= 2 ? '🚨 CRITICAL' : '⚠️  WARNING'} from ${ip} — status set to ${severity}`);
    return res.status(201).json({ status: 'ok', message: 'Alert logged', severity });
  } catch (err) {
    console.error('[ESP32] Alert ingest error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ============================================================
// GET /api/esp32/status — Hardware sensor heartbeat
// ESP32 can ping this, or dashboard polls it to show sensor state
// ============================================================
let lastEsp32Ping = null;

router.post('/api/esp32/ping', (req, res) => {
  lastEsp32Ping = Date.now();
  res.json({ status: 'ok' });
});

router.get('/api/esp32/status', (req, res) => {
  const OFFLINE_THRESHOLD_MS = 3 * 60 * 1000; // 3 minutes — generous for slow networks
  const online = lastEsp32Ping && (Date.now() - lastEsp32Ping) < OFFLINE_THRESHOLD_MS;
  res.json({
    online: !!online,
    last_ping: lastEsp32Ping ? new Date(lastEsp32Ping).toISOString() : null,
    sensor_ip: '192.168.1.30'
  });
});

module.exports = router;
