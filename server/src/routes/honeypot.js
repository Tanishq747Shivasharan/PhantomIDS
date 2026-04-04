'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../db/database');

let lastEsp32Ping = null;

function logAttack(req, payload) {
  const ip        = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const status    = req.ipStatus || (() => {
    const tracker = db.prepare('SELECT status FROM ip_tracker WHERE ip = ?').get(ip);
    return tracker ? tracker.status : 'NORMAL';
  })();

  try {
    db.prepare(`
      INSERT INTO attack_log (ip, method, path, payload, user_agent, status)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(ip, req.method, req.originalUrl, payload, userAgent, status);
  } catch (err) {
    console.error('[Honeypot] DB log error:', err.message);
  }
}

// Intentionally vulnerable login endpoint — DO NOT sanitize
router.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const payload = `username=${username}&password=${password}`;

  // Skip logging for ESP32-forwarded requests — /api/esp32/alert handles those
  if (!req.headers['x-forwarded-for']) {
    logAttack(req, payload);
  }

  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  let result   = null;
  let sqlError = null;

  try {
    result = db.prepare(query).get();
  } catch (err) {
    sqlError = err.message;
    console.log(`[Honeypot] SQL Error from ${req.ip}: ${err.message}`);
  }

  if (sqlError) {
    return res.status(200).json({
      success: false,
      message: 'An internal error occurred. Please try again.',
      debug: sqlError,
    });
  }

  if (result) {
    return res.status(200).json({
      success: true,
      message: `Welcome back, ${result.username}!`,
      role: result.role,
      redirect: '/employee-portal',
    });
  }

  return res.status(200).json({ success: false, message: 'Invalid username or password.' });
});

router.get('/honeypot-status', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as total FROM attack_log').get();
  res.json({ status: 'ACTIVE', total_attacks_logged: count.total });
});

// ESP32 posts here when it detects SQLi: { attacker_ip, payload, score }
router.post('/api/esp32/alert', (req, res) => {
  const { attacker_ip, payload, score } = req.body;

  if (!attacker_ip) {
    return res.status(400).json({ error: 'attacker_ip is required' });
  }

  const ip       = attacker_ip;
  const severity = score >= 2 ? 'BANNED' : 'THREAT';

  try {
    // Update the most recent row from this IP (forwarded by ESP32) within 30s
    const updated = db.prepare(`
      UPDATE attack_log SET status = ?
      WHERE id = (
        SELECT id FROM attack_log
        WHERE ip = ? AND datetime(timestamp) >= datetime('now', '-30 seconds')
        ORDER BY id DESC LIMIT 1
      )
    `).run(severity, ip);

    if (updated.changes === 0) {
      db.prepare(`
        INSERT INTO attack_log (ip, method, path, payload, user_agent, status)
        VALUES (?, 'POST', '/login', ?, 'ESP32-PhantomIDS/1.0', ?)
      `).run(ip, payload || '', severity);
    }

    const existing = db.prepare('SELECT * FROM ip_tracker WHERE ip = ?').get(ip);
    if (existing) {
      db.prepare(`
        UPDATE ip_tracker
        SET status = CASE WHEN status != 'BANNED' THEN ? ELSE 'BANNED' END
        WHERE ip = ?
      `).run(severity, ip);
    } else {
      db.prepare(`
        INSERT INTO ip_tracker (ip, request_count, window_start, status, threat_count)
        VALUES (?, 1, datetime('now'), ?, 1)
      `).run(ip, severity);
    }

    lastEsp32Ping = Date.now();
    console.log(`[ESP32] ${score >= 2 ? 'CRITICAL' : 'WARNING'} from ${ip} — ${severity}`);
    return res.status(201).json({ status: 'ok', message: 'Alert logged', severity });
  } catch (err) {
    console.error('[ESP32] Alert ingest error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

router.post('/api/esp32/ping', (req, res) => {
  lastEsp32Ping = Date.now();
  res.json({ status: 'ok' });
});

router.get('/api/esp32/status', (req, res) => {
  const online = lastEsp32Ping && (Date.now() - lastEsp32Ping) < 3 * 60 * 1000;
  res.json({
    online: !!online,
    last_ping: lastEsp32Ping ? new Date(lastEsp32Ping).toISOString() : null,
    sensor_ip: '192.168.1.30',
  });
});

module.exports = router;
