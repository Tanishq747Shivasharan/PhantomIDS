const express = require('express');
const router = express.Router();
const db = require('../db/database');

// ============================================================
// AUTH MIDDLEWARE — protect all dashboard API routes
// ============================================================
function requireAuth(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// ============================================================
// GET /api/stats — Summary statistics
// ============================================================
router.get('/api/stats', requireAuth, (req, res) => {
  try {
    const total    = db.prepare('SELECT COUNT(*) as n FROM attack_log').get().n;
    const unique   = db.prepare('SELECT COUNT(DISTINCT ip) as n FROM attack_log').get().n;
    const threats  = db.prepare("SELECT COUNT(*) as n FROM attack_log WHERE status = 'THREAT'").get().n;
    const banned   = db.prepare("SELECT COUNT(DISTINCT ip) as n FROM attack_log WHERE status = 'BANNED'").get().n;
    const lastHour = db.prepare(`
      SELECT COUNT(*) as n FROM attack_log
      WHERE timestamp >= datetime('now', '-1 hour')
    `).get().n;

    res.json({ total, unique, threats, banned, lastHour });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// GET /api/attacks — Paginated attack log
// ============================================================
router.get('/api/attacks', requireAuth, (req, res) => {
  const page  = parseInt(req.query.page)  || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  const filter = req.query.status || null; // NORMAL | THREAT | BANNED

  try {
    let query = 'SELECT * FROM attack_log';
    let countQuery = 'SELECT COUNT(*) as total FROM attack_log';
    const params = [];

    if (filter) {
      query += ' WHERE status = ?';
      countQuery += ' WHERE status = ?';
      params.push(filter);
    }

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    const rows = db.prepare(query).all(...params, limit, offset);
    const total = db.prepare(countQuery).get(...params).total;

    res.json({ attacks: rows, total, page, limit });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// GET /api/top-ips — Top attacking IPs
// ============================================================
router.get('/api/top-ips', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT ip, COUNT(*) as count, MAX(timestamp) as last_seen, status
      FROM attack_log
      GROUP BY ip
      ORDER BY count DESC
      LIMIT 10
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// GET /api/timeline — Attack counts per hour (last 24h)
// ============================================================
router.get('/api/timeline', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
      FROM attack_log
      WHERE timestamp >= datetime('now', '-24 hours')
      GROUP BY hour
      ORDER BY hour ASC
    `).all();
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// POST /api/ban/:ip — Ban an IP address
// ============================================================
router.post('/api/ban/:ip', requireAuth, (req, res) => {
  const ip = decodeURIComponent(req.params.ip);

  try {
    db.prepare("UPDATE attack_log SET status = 'BANNED' WHERE ip = ?").run(ip);
    db.prepare("UPDATE ip_tracker SET status = 'BANNED' WHERE ip = ?").run(ip);

    console.log(`[Dashboard] 🚫 Admin banned IP: ${ip}`);
    res.json({ success: true, message: `IP ${ip} has been banned.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// POST /api/unban/:ip — Unban an IP address
// ============================================================
router.post('/api/unban/:ip', requireAuth, (req, res) => {
  const ip = decodeURIComponent(req.params.ip);

  try {
    db.prepare("UPDATE attack_log SET status = 'NORMAL' WHERE ip = ? AND status = 'BANNED'").run(ip);
    db.prepare("UPDATE ip_tracker SET status = 'NORMAL' WHERE ip = ? AND status = 'BANNED'").run(ip);

    res.json({ success: true, message: `IP ${ip} has been unbanned.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// DELETE /api/clear-logs — Clear all attack logs (admin only)
// ============================================================
router.delete('/api/clear-logs', requireAuth, (req, res) => {
  try {
    db.prepare('DELETE FROM attack_log').run();
    db.prepare('DELETE FROM ip_tracker').run();
    res.json({ success: true, message: 'All logs cleared.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
