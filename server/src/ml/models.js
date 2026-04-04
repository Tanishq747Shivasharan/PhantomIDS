'use strict';

const fs   = require('fs');
const path = require('path');

const MODEL_PATH = path.join(__dirname, 'model.json');

function buildFallbackModel() {
  return {
    algorithm:  'Logistic Regression (fallback weights)',
    version:    '2.0.0-fallback',
    weights:    [4.948, 3.853],
    bias:       -2.044,
    norm:       { requestRate: { min: 1, max: 80 }, threatCount: { min: 0, max: 3 } },
    metrics:    { accuracy: 86.14, precision: 87.93, recall: 87.93, f1: 87.93 },
    classificationThreshold: 0.5,
  };
}

function loadModel() {
  try {
    if (!fs.existsSync(MODEL_PATH)) {
      console.warn('[ML-Model1] model.json not found — using fallback weights. Run: npm run train');
      return buildFallbackModel();
    }

    const saved = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));

    if (!saved.weights || saved.weights.length < 2 || saved.bias === undefined || !saved.norm) {
      throw new Error('model.json is malformed — missing weights/bias/norm');
    }

    console.log(`[ML-Model1] Logistic Regression loaded`);
    console.log(`            w1=${saved.weights[0]}  w2=${saved.weights[1]}  bias=${saved.bias}`);
    console.log(`            Accuracy: ${saved.metrics?.accuracy}%  F1: ${saved.metrics?.f1}%`);
    console.log(`            Trained on ${saved.trainingSamples} samples (${saved.trainedAt})`);

    return saved;
  } catch (err) {
    console.error('[ML-Model1] Load error:', err.message, '— using fallback weights.');
    return buildFallbackModel();
  }
}

const SAVED_MODEL = loadModel();

/** sigmoid(z) = 1 / (1 + e^-z) — maps any real number to (0, 1) */
function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

/** Normalizes value to [0, 1] using the same bounds recorded during training */
function minMaxNormalize(value, min, max) {
  const range   = max - min || 1;
  const clamped = Math.max(min, Math.min(max, value));
  return (clamped - min) / range;
}

const ML_MODEL_1 = {
  name:        'Behavioural Anomaly Detector',
  algorithm:   'Logistic Regression (Binary Cross-Entropy)',
  description: 'Computes P(THREAT) via sigmoid over normalized request_rate and threat_count.',
  version:     SAVED_MODEL.version || '2.0.0',

  hyperparams: {
    WEIGHTS:           SAVED_MODEL.weights,
    BIAS:              SAVED_MODEL.bias,
    THRESHOLD:         SAVED_MODEL.classificationThreshold || 0.5,
    NORM_REQUEST_RATE: SAVED_MODEL.norm.requestRate,
    NORM_THREAT_COUNT: SAVED_MODEL.norm.threatCount,
    TRAINING_ACCURACY: SAVED_MODEL.metrics?.accuracy,
    TRAINING_F1:       SAVED_MODEL.metrics?.f1,
    NORMAL_LABEL:      'NORMAL',
    THREAT_LABEL:      'THREAT',
    WINDOW_MS:         60 * 1000,
    THREAT_THRESHOLD:  20,
  },

  /**
   * Classifies an IP as NORMAL or THREAT using logistic regression.
   * z = w1·norm(request_rate) + w2·norm(threat_count) + bias
   * P(THREAT) = sigmoid(z)
   *
   * @param {object} features
   * @param {number} features.requestCount  - requests in current window
   * @param {number} features.windowMs      - elapsed window time in ms
   * @param {number} features.threatCount   - accumulated strike history
   * @param {string} features.currentStatus - current DB status
   */
  predict({ requestCount, windowMs, currentStatus, threatCount = 0 }) {
    const hp = ML_MODEL_1.hyperparams;

    if (currentStatus === 'BANNED') {
      return { label: 'BANNED', probability: 1.0, confidence: 1.0, features: {}, reason: 'IP is permanently banned.', modelUsed: hp.algorithm };
    }

    const elapsedMin  = Math.max(windowMs / 60000, 1 / 60);
    const requestRate = requestCount / elapsedMin;
    const x1_norm     = minMaxNormalize(requestRate, hp.NORM_REQUEST_RATE.min, hp.NORM_REQUEST_RATE.max);
    const x2_norm     = minMaxNormalize(threatCount, hp.NORM_THREAT_COUNT.min, hp.NORM_THREAT_COUNT.max);
    const z           = hp.WEIGHTS[0] * x1_norm + hp.WEIGHTS[1] * x2_norm + hp.BIAS;
    const probability = sigmoid(z);
    const isThreat    = probability >= hp.THRESHOLD;
    const label       = isThreat ? hp.THREAT_LABEL : hp.NORMAL_LABEL;
    const confidence  = parseFloat((Math.abs(probability - 0.5) * 2).toFixed(3));

    return {
      label,
      probability: parseFloat(probability.toFixed(4)),
      confidence,
      features: {
        requestCount,
        requestRate:     parseFloat(requestRate.toFixed(2)),
        requestRateNorm: parseFloat(x1_norm.toFixed(4)),
        threatCount,
        threatCountNorm: parseFloat(x2_norm.toFixed(4)),
        linearScore_z:   parseFloat(z.toFixed(4)),
        windowSeconds:   parseFloat((windowMs / 1000).toFixed(1)),
        threshold:       hp.THRESHOLD,
        currentStatus,
      },
      reason: isThreat
        ? `P(THREAT)=${(probability*100).toFixed(1)}% >= 50% | rate=${requestRate.toFixed(1)} req/min, strikes=${threatCount}`
        : `P(THREAT)=${(probability*100).toFixed(1)}% < 50% | rate=${requestRate.toFixed(1)} req/min`,
      modelUsed: ML_MODEL_1.algorithm,
    };
  },
};

const ML_MODEL_2 = {
  name:        '3-Strike Auto-Ban Classifier',
  algorithm:   'Accumulative Strike Committee (Ensemble)',
  description: 'Counts Model 1 THREAT votes per IP. After 3 strikes → permanent ban.',
  version:     '2.0.0',

  hyperparams: {
    BAN_STRIKES:  3,
    THREAT_LABEL: 'THREAT',
    BAN_LABEL:    'BANNED',
  },

  /**
   * @param {object} features
   * @param {number} features.threatStrikes  - accumulated Model 1 THREAT votes
   * @param {string} features.model1Decision - current Model 1 label
   * @param {string} features.currentStatus  - current DB status
   */
  predict({ threatStrikes, model1Decision, currentStatus }) {
    const { BAN_STRIKES, THREAT_LABEL, BAN_LABEL } = ML_MODEL_2.hyperparams;

    if (currentStatus === 'BANNED') {
      return { label: BAN_LABEL, confidence: 1.0, features: {}, reason: `Already banned (${threatStrikes} strikes).`, action: 'NONE' };
    }

    if (model1Decision === THREAT_LABEL) {
      const newStrikes = threatStrikes + 1;
      const shouldBan  = newStrikes >= BAN_STRIKES;
      return {
        label:      shouldBan ? BAN_LABEL : THREAT_LABEL,
        confidence: shouldBan ? 1.0 : parseFloat((newStrikes / BAN_STRIKES).toFixed(3)),
        features:   { previousStrikes: threatStrikes, newStrikes, banThreshold: BAN_STRIKES, votesRemaining: Math.max(0, BAN_STRIKES - newStrikes) },
        reason:     shouldBan
          ? `Strike ${newStrikes}/${BAN_STRIKES} — AUTO-BAN triggered.`
          : `Strike ${newStrikes}/${BAN_STRIKES} — ${BAN_STRIKES - newStrikes} more to ban.`,
        action: shouldBan ? 'BAN_IP' : 'FLAG_THREAT',
      };
    }

    return {
      label:      currentStatus || 'NORMAL',
      confidence: 1.0,
      features:   { strikes: threatStrikes, banThreshold: BAN_STRIKES },
      reason:     'Model 1 classified NORMAL — no action.',
      action:     'NONE',
    };
  },
};

/**
 * Runs both models in sequence on an ip_tracker record.
 * @returns {{ ip, model1, model2, finalDecision, timestamp }}
 */
function runMLPipeline(ipRecord, now = Date.now()) {
  const windowMs = Math.max(now - new Date(ipRecord.window_start).getTime(), 0);

  const model1Result = ML_MODEL_1.predict({
    requestCount:  ipRecord.request_count || 0,
    windowMs,
    threatCount:   ipRecord.threat_count  || 0,
    currentStatus: ipRecord.status        || 'NORMAL',
  });

  const model2Result = ML_MODEL_2.predict({
    threatStrikes:  ipRecord.threat_count || 0,
    model1Decision: model1Result.label,
    currentStatus:  ipRecord.status       || 'NORMAL',
  });

  const priority    = { BANNED: 3, THREAT: 2, NORMAL: 1 };
  const finalStatus = (priority[model2Result.label] || 1) >= (priority[model1Result.label] || 1)
    ? model2Result.label : model1Result.label;

  return {
    ip:            ipRecord.ip,
    model1:        { modelName: ML_MODEL_1.name, ...model1Result },
    model2:        { modelName: ML_MODEL_2.name, ...model2Result },
    finalDecision: finalStatus,
    timestamp:     new Date(now).toISOString(),
  };
}

module.exports = {
  ML_MODEL_1,
  ML_MODEL_2,
  runMLPipeline,
  MODEL_METADATA: {
    model1: {
      name:        ML_MODEL_1.name,
      algorithm:   ML_MODEL_1.algorithm,
      description: ML_MODEL_1.description,
      version:     ML_MODEL_1.version,
      hyperparams: { weights: SAVED_MODEL.weights, bias: SAVED_MODEL.bias, threshold: SAVED_MODEL.classificationThreshold, norm: SAVED_MODEL.norm },
      metrics:     SAVED_MODEL.metrics,
    },
    model2: {
      name:        ML_MODEL_2.name,
      algorithm:   ML_MODEL_2.algorithm,
      description: ML_MODEL_2.description,
      version:     ML_MODEL_2.version,
      hyperparams: ML_MODEL_2.hyperparams,
    },
  },
};
