const db = require('../db/database');
const { ML_MODEL_1, ML_MODEL_2 } = require('../ml/models');

// ============================================================
// PhantomIDS — Threat Detection Middleware
//
// This middleware runs on EVERY incoming request.
// It orchestrates the two ML models defined in src/ml/models.js
//
//  ┌─────────────────────────────────────────────────────────┐
//  │  ML MODEL 1 — Behavioural Anomaly Detector              │
//  │    Tracks request rate per IP in a 60-second window.    │
//  │    Flags as THREAT when rate > 20 req/min.              │
//  ├─────────────────────────────────────────────────────────┤
//  │  ML MODEL 2 — 3-Strike Auto-Ban Classifier              │
//  │    Counts how many times Model 1 has flagged this IP.   │
//  │    After 3 THREAT flags → permanently bans the IP.      │
//  └─────────────────────────────────────────────────────────┘
// ============================================================

// Read hyper-parameters directly from the model objects
const WINDOW_MS        = ML_MODEL_1.hyperparams.WINDOW_MS;
const THREAT_THRESHOLD = ML_MODEL_1.hyperparams.THREAT_THRESHOLD;
const BAN_STRIKES      = ML_MODEL_2.hyperparams.BAN_STRIKES;

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

    // ── ML MODEL 2 gate: Already banned — keep logging silently ──
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

    // ── ML MODEL 1: Logistic Regression ────────────────────────────────────
    const model1 = ML_MODEL_1.predict({
      requestCount:  newCount,
      windowMs:      elapsed,
      threatCount:   tracker.threat_count || 0,   // ← feature 2 for logistic regression
      currentStatus: tracker.status,
    });

    if (model1.label === 'THREAT' && tracker.status === 'NORMAL') {
      const newStrikes = (tracker.threat_count || 0) + 1;
      db.prepare('UPDATE ip_tracker SET threat_count = ? WHERE ip = ?').run(newStrikes, ip);

      // ── ML MODEL 2: 3-Strike Auto-Ban Classifier ───────────
      const model2 = ML_MODEL_2.predict({
        threatStrikes:  newStrikes,
        model1Decision: model1.label,
        currentStatus:  tracker.status,
      });

      if (model2.action === 'BAN_IP') {
        // Model 2 fires: ban this IP permanently
        db.prepare("UPDATE ip_tracker SET status = 'BANNED' WHERE ip = ?").run(ip);
        db.prepare("UPDATE attack_log SET status = 'BANNED' WHERE ip = ?").run(ip);
        console.log(
          `[ML-Model2] 🚫 AUTO-BANNED: ${ip}` +
          ` | Strike ${newStrikes}/${BAN_STRIKES} — ban threshold reached` +
          ` | Confidence: ${(model2.confidence * 100).toFixed(0)}%`
        );
        req.ipStatus = 'BANNED';
      } else {
        // Model 1 fires: flag as threat, Model 2 accumulates
        db.prepare("UPDATE ip_tracker SET status = 'THREAT' WHERE ip = ?").run(ip);
        db.prepare(`
          UPDATE attack_log SET status = 'THREAT'
          WHERE ip = ? AND status = 'NORMAL'
        `).run(ip);
        console.log(
          `[ML-Model1] ⚠️  THREAT flagged: ${ip}` +
          ` | ${newCount} req/${(elapsed/1000).toFixed(0)}s` +
          ` | Strike ${newStrikes}/${BAN_STRIKES}` +
          ` | Confidence: ${(model1.confidence * 100).toFixed(0)}%` +
          ` | Reason: ${model1.reason}`
        );
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
