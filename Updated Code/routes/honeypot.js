const express = require('express');
const router = express.Router();
const db = require('../db/database');

// ============================================================
// INTENTIONALLY VULNERABLE HONEYPOT LOGIN
// Purpose: Attract and log SQL injection attacks from sqlmap
// WARNING: This is deliberately insecure by design.
// ============================================================

function logAttack(req, payload) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
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

module.exports = router;
