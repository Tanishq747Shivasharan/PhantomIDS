const db = require('../db/database');

// ============================================================
// ML MODEL 1 — Behavioural Threat Detection
//   Tracks request rate per IP in a 60-second sliding window.
//   Auto-flags as THREAT when > 20 req/min (bot threshold).
//
// ML MODEL 2 — Active Prevention & Auto-Ban (3-Strikes Rule)
//   Counts how many times an IP has been flagged THREAT.
//   After 3 THREAT detections → auto-ban the IP permanently.
// ============================================================

const WINDOW_MS        = 60 * 1000; // 60-second sliding window
const THREAT_THRESHOLD = 20;         // > 20 req/min = bot behaviour
const BAN_STRIKES      = 3;          // 3 THREAT flags = auto-ban

// In-memory strike counter per IP (resets on server restart)
// Backed by ip_tracker.threat_count in DB for persistence
const strikeCache = {};

function threatDetector(req, res, next) {
  const ip  = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();

  try {
    let tracker = db.prepare('SELECT * FROM ip_tracker WHERE ip = ?').get(ip);

    // ── First request from this IP ──────────────────────────
    if (!tracker) {
      db.prepare(`
        INSERT INTO ip_tracker (ip, request_count, window_start, status, threat_count)
        VALUES (?, 1, datetime('now'), 'NORMAL', 0)
      `).run(ip);
      req.ipStatus = 'NORMAL';
      return next();
    }

    // ── Already banned — keep logging silently ──────────────
    if (tracker.status === 'BANNED') {
      req.ipStatus = 'BANNED';
      return next();
    }

    const windowStart = new Date(tracker.window_start).getTime();
    const elapsed     = now - windowStart;

    // ── Reset window if 60s has passed ─────────────────────
    if (elapsed > WINDOW_MS) {
      db.prepare(`
        UPDATE ip_tracker
        SET request_count = 1, window_start = datetime('now')
        WHERE ip = ?
      `).run(ip);
      req.ipStatus = tracker.status;
      return next();
    }

    // ── Increment request count in current window ───────────
    const newCount = tracker.request_count + 1;
    db.prepare('UPDATE ip_tracker SET request_count = ? WHERE ip = ?').run(newCount, ip);

    // ── ML MODEL 1: Behavioural detection ──────────────────
    if (newCount > THREAT_THRESHOLD && tracker.status === 'NORMAL') {
      // Increment strike counter
      const strikes = (tracker.threat_count || 0) + 1;
      db.prepare('UPDATE ip_tracker SET threat_count = ? WHERE ip = ?').run(strikes, ip);

      // ── ML MODEL 2: 3-Strikes auto-ban ─────────────────
      if (strikes >= BAN_STRIKES) {
        db.prepare("UPDATE ip_tracker SET status = 'BANNED' WHERE ip = ?").run(ip);
        db.prepare("UPDATE attack_log SET status = 'BANNED' WHERE ip = ?").run(ip);
        console.log(`[ML-Model2] 🚫 AUTO-BANNED: ${ip} (${strikes} strikes — exceeded 3-strike threshold)`);
        req.ipStatus = 'BANNED';
      } else {
        db.prepare("UPDATE ip_tracker SET status = 'THREAT' WHERE ip = ?").run(ip);
        db.prepare(`
          UPDATE attack_log SET status = 'THREAT'
          WHERE ip = ? AND status = 'NORMAL'
        `).run(ip);
        console.log(`[ML-Model1] ⚠️  THREAT flagged: ${ip} (${newCount} req/60s | strike ${strikes}/${BAN_STRIKES})`);
        req.ipStatus = 'THREAT';
      }
    } else {
      req.ipStatus = tracker.status;
    }

  } catch (err) {
    // Non-critical — never crash on detection errors
    console.error('[ThreatDetector] Error:', err.message);
  }

  next();
}

module.exports = threatDetector;
