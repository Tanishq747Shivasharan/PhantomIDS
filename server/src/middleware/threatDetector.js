'use strict';

const db = require('../db/database');
const { ML_MODEL_1, ML_MODEL_2 } = require('../ml/models');

const WINDOW_MS   = ML_MODEL_1.hyperparams.WINDOW_MS;
const BAN_STRIKES = ML_MODEL_2.hyperparams.BAN_STRIKES;

function threatDetector(req, res, next) {
  const ip  = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();

  try {
    let tracker = db.prepare('SELECT * FROM ip_tracker WHERE ip = ?').get(ip);

    if (!tracker) {
      db.prepare(`
        INSERT INTO ip_tracker (ip, request_count, window_start, status, threat_count)
        VALUES (?, 1, datetime('now'), 'NORMAL', 0)
      `).run(ip);
      req.ipStatus = 'NORMAL';
      return next();
    }

    if (tracker.status === 'BANNED') {
      req.ipStatus = 'BANNED';
      return next();
    }

    const elapsed = now - new Date(tracker.window_start).getTime();

    if (elapsed > WINDOW_MS) {
      db.prepare(`
        UPDATE ip_tracker SET request_count = 1, window_start = datetime('now') WHERE ip = ?
      `).run(ip);
      req.ipStatus = tracker.status;
      return next();
    }

    const newCount = tracker.request_count + 1;
    db.prepare('UPDATE ip_tracker SET request_count = ? WHERE ip = ?').run(newCount, ip);

    const model1 = ML_MODEL_1.predict({
      requestCount:  newCount,
      windowMs:      elapsed,
      threatCount:   tracker.threat_count || 0,
      currentStatus: tracker.status,
    });

    if (model1.label === 'THREAT' && tracker.status === 'NORMAL') {
      const newStrikes = (tracker.threat_count || 0) + 1;
      db.prepare('UPDATE ip_tracker SET threat_count = ? WHERE ip = ?').run(newStrikes, ip);

      const model2 = ML_MODEL_2.predict({
        threatStrikes:  newStrikes,
        model1Decision: model1.label,
        currentStatus:  tracker.status,
      });

      if (model2.action === 'BAN_IP') {
        db.prepare("UPDATE ip_tracker SET status = 'BANNED' WHERE ip = ?").run(ip);
        db.prepare("UPDATE attack_log SET status = 'BANNED' WHERE ip = ?").run(ip);
        console.log(`[ML-Model2] AUTO-BANNED: ${ip} | Strike ${newStrikes}/${BAN_STRIKES} | Confidence: ${(model2.confidence * 100).toFixed(0)}%`);
        req.ipStatus = 'BANNED';
      } else {
        db.prepare("UPDATE ip_tracker SET status = 'THREAT' WHERE ip = ?").run(ip);
        db.prepare("UPDATE attack_log SET status = 'THREAT' WHERE ip = ? AND status = 'NORMAL'").run(ip);
        console.log(`[ML-Model1] THREAT: ${ip} | ${newCount} req/${(elapsed/1000).toFixed(0)}s | Strike ${newStrikes}/${BAN_STRIKES} | Confidence: ${(model1.confidence * 100).toFixed(0)}%`);
        req.ipStatus = 'THREAT';
      }
    } else {
      req.ipStatus = tracker.status;
    }

  } catch (err) {
    console.error('[ThreatDetector] Error:', err.message);
  }

  next();
}

module.exports = threatDetector;
