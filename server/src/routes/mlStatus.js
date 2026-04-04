'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../db/database');
const { ML_MODEL_1, ML_MODEL_2, MODEL_METADATA, runMLPipeline } = require('../ml/models');

function requireAuth(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

router.get('/api/ml/status', requireAuth, (req, res) => {
  try {
    const totalIPs   = db.prepare('SELECT COUNT(*) as n FROM ip_tracker').get().n;
    const normalIPs  = db.prepare("SELECT COUNT(*) as n FROM ip_tracker WHERE status = 'NORMAL'").get().n;
    const threatIPs  = db.prepare("SELECT COUNT(*) as n FROM ip_tracker WHERE status = 'THREAT'").get().n;
    const bannedIPs  = db.prepare("SELECT COUNT(*) as n FROM ip_tracker WHERE status = 'BANNED'").get().n;
    const totalLogs  = db.prepare('SELECT COUNT(*) as n FROM attack_log').get().n;
    const avgReqRate = db.prepare('SELECT AVG(request_count) as avg FROM ip_tracker').get().avg || 0;

    const recentBans = db.prepare(`
      SELECT ip, threat_count, window_start FROM ip_tracker
      WHERE status = 'BANNED' ORDER BY rowid DESC LIMIT 10
    `).all();

    res.json({
      models: {
        model1: {
          ...MODEL_METADATA.model1,
          status:         'ACTIVE',
          decisionsToday: threatIPs + bannedIPs,
          threatsFlagged: threatIPs,
          inputFeature:   'request_rate_per_minute',
        },
        model2: {
          ...MODEL_METADATA.model2,
          status:       'ACTIVE',
          bansFired:    bannedIPs,
          recentBans,
          inputFeature: 'threat_strike_count',
        },
      },
      aggregates: {
        totalTrackedIPs:  totalIPs,
        normalIPs,
        threatIPs,
        bannedIPs,
        totalAttackLogs:  totalLogs,
        avgReqRatePerMin: parseFloat(avgReqRate.toFixed(2)),
      },
      pipeline:  'Model1 (rate) → Model2 (strikes) → Final Decision',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/api/ml/analyze/:ip', requireAuth, (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  try {
    const ipRecord = db.prepare('SELECT * FROM ip_tracker WHERE ip = ?').get(ip);

    if (!ipRecord) {
      return res.json({
        ip,
        found:           false,
        message:         'IP not in tracker — no history to analyze.',
        defaultDecision: 'NORMAL',
        timestamp:       new Date().toISOString(),
      });
    }

    res.json({ ip, found: true, ...runMLPipeline(ipRecord, Date.now()) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/api/ml/feed', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT t.ip, t.request_count, t.threat_count, t.status, t.window_start,
        (SELECT COUNT(*) FROM attack_log WHERE ip = t.ip) AS total_requests
      FROM ip_tracker t
      WHERE t.status IN ('THREAT', 'BANNED')
      ORDER BY t.rowid DESC LIMIT 20
    `).all();

    const feed = rows.map(row => {
      const result = runMLPipeline(row, Date.now());
      return {
        ip:            row.ip,
        currentStatus: row.status,
        totalRequests: row.total_requests,
        model1:        { label: result.model1.label, confidence: result.model1.confidence, reason: result.model1.reason },
        model2:        { label: result.model2.label, confidence: result.model2.confidence, reason: result.model2.reason, action: result.model2.action },
        finalDecision: result.finalDecision,
        timestamp:     result.timestamp,
      };
    });

    res.json({ feed, count: feed.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
