/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║          PhantomIDS — Machine Learning Engine v2.0              ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  ML Model 1: Logistic Regression (trained, loaded from disk)    ║
 * ║  ML Model 2: 3-Strike Auto-Ban Classifier (rule-based ensemble) ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 *  HOW MODEL 1 WORKS (Logistic Regression)
 *  ─────────────────────────────────────────
 *  During training (scripts/train-model.js):
 *    1. Features extracted: [request_rate, threat_count]
 *    2. Normalize each feature to [0, 1] using min-max scaling
 *    3. Gradient descent minimizes binary cross-entropy loss:
 *         J = -[y·log(p) + (1-y)·log(1-p)]
 *    4. Weights [w1, w2] and bias b saved to src/ml/model.json
 *
 *  At runtime (this file):
 *    1. Load weights from model.json at server start
 *    2. For each IP: compute z = w1·x1_norm + w2·x2_norm + b
 *    3. P(THREAT) = sigmoid(z) = 1 / (1 + e^-z)
 *    4. Label = P(THREAT) ≥ 0.5 ? 'THREAT' : 'NORMAL'
 *
 *  HOW MODEL 2 WORKS (Ensemble Strike Committee)
 *  ───────────────────────────────────────────────
 *  Uses ML Model 1's output label as input.
 *  Each THREAT vote = 1 strike. After 3 strikes → permanent IP ban.
 *  Analogous to ensemble committee machine (majority vote with k=3).
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ════════════════════════════════════════════════════════════════════════════
// MODEL LOADING — Load trained weights from model.json at server startup
// ════════════════════════════════════════════════════════════════════════════

const MODEL_PATH = path.join(__dirname, 'model.json');

/**
 * loadModel() — reads and validates the model.json file.
 * Falls back to safe default weights if the file is missing.
 * This function runs ONCE at require() time (module cache).
 */
function loadModel() {
  try {
    if (!fs.existsSync(MODEL_PATH)) {
      console.warn('[ML-Model1] ⚠️  model.json not found — using fallback weights.');
      console.warn('            Run: node scripts/train-model.js');
      return buildFallbackModel();
    }

    const raw     = fs.readFileSync(MODEL_PATH, 'utf8');
    const saved   = JSON.parse(raw);

    // Validate required fields
    if (!saved.weights || saved.weights.length < 2 || saved.bias === undefined || !saved.norm) {
      throw new Error('model.json is malformed — missing weights/bias/norm');
    }

    console.log(`[ML-Model1] ✓  Logistic Regression loaded`);
    console.log(`            Weights → w1=${saved.weights[0]}  w2=${saved.weights[1]}  bias=${saved.bias}`);
    console.log(`            Accuracy: ${saved.metrics?.accuracy}%  |  F1: ${saved.metrics?.f1}%`);
    console.log(`            Trained on ${saved.trainingSamples} samples (${saved.trainedAt})`);

    return saved;
  } catch (err) {
    console.error('[ML-Model1] model.json load error:', err.message, '— using fallback weights.');
    return buildFallbackModel();
  }
}

/** Fallback model with manually chosen safe weights (no training required) */
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

// Load once at module startup — cached by Node.js require() system
const SAVED_MODEL = loadModel();

// ════════════════════════════════════════════════════════════════════════════
// PURE MATH HELPERS (no external libraries needed)
// ════════════════════════════════════════════════════════════════════════════

/**
 * sigmoid(z) → number in (0, 1)
 *
 * The activation function used in logistic regression.
 * Maps any real number to a probability between 0 and 1.
 *
 *   sigmoid(z) = 1 / (1 + e^-z)
 *
 * Examples:
 *   sigmoid(-3)  ≈ 0.047  → very likely NORMAL
 *   sigmoid( 0)  = 0.500  → decision boundary
 *   sigmoid(+3)  ≈ 0.953  → very likely THREAT
 */
function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

/**
 * minMaxNormalize(value, min, max) → [0, 1]
 *
 * Normalizes a raw feature value to [0, 1] using the same
 * bounds recorded during training. This MUST match the training
 * normalization exactly, otherwise weights are meaningless.
 */
function minMaxNormalize(value, min, max) {
  const range = max - min || 1;         // guard against zero range
  const clamped = Math.max(min, Math.min(max, value)); // clamp to training range
  return (clamped - min) / range;
}

// ════════════════════════════════════════════════════════════════════════════
// ML MODEL 1 — Logistic Regression Classifier
// ════════════════════════════════════════════════════════════════════════════

const ML_MODEL_1 = {
  name:        'Behavioural Anomaly Detector',
  algorithm:   'Logistic Regression (Binary Cross-Entropy)',
  description: 'Trained on historical IP request patterns. Computes P(THREAT) ' +
               'using a sigmoid function over normalized request_rate and threat_count. ' +
               'Analogous to spam/not-spam Naive Bayes classification by feature frequency.',
  version:     SAVED_MODEL.version || '2.0.0',

  // ── Live model parameters (loaded from model.json) ────────────────────
  hyperparams: {
    WEIGHTS:              SAVED_MODEL.weights,   // [w1, w2]
    BIAS:                 SAVED_MODEL.bias,
    THRESHOLD:            SAVED_MODEL.classificationThreshold || 0.5,
    NORM_REQUEST_RATE:    SAVED_MODEL.norm.requestRate,   // { min, max }
    NORM_THREAT_COUNT:    SAVED_MODEL.norm.threatCount,   // { min, max }
    TRAINING_ACCURACY:    SAVED_MODEL.metrics?.accuracy,
    TRAINING_F1:          SAVED_MODEL.metrics?.f1,
    NORMAL_LABEL:         'NORMAL',
    THREAT_LABEL:         'THREAT',
  },

  /**
   * predict(features) → { label, confidence, probability, features, reason }
   *
   * STEP-BY-STEP:
   *   1. Extract raw features: request_rate (req/min) and threat_count (strikes)
   *   2. Normalize each feature using saved min-max bounds
   *   3. Compute linear combination: z = w1·x1_norm + w2·x2_norm + bias
   *   4. Apply sigmoid to get probability: P(THREAT) = σ(z)
   *   5. Apply threshold (0.5): label = P ≥ 0.5 ? THREAT : NORMAL
   *   6. Return structured result compatible with the existing pipeline
   *
   * @param {object} features
   *   @param {number} features.requestCount   - raw request count in window
   *   @param {number} features.windowMs       - elapsed window time in ms
   *   @param {number} features.threatCount    - accumulated strike history
   *   @param {string} features.currentStatus  - current DB status
   */
  predict(features) {
    const hp = ML_MODEL_1.hyperparams;
    const { requestCount, windowMs, currentStatus, threatCount = 0 } = features;

    // Already banned — skip classification
    if (currentStatus === 'BANNED') {
      return {
        label:       'BANNED',
        probability: 1.0,
        confidence:  1.0,
        features:    {},
        reason:      'IP is permanently banned by Model 2 — no classification needed.',
        modelUsed:   ML_MODEL_1.algorithm,
      };
    }

    // ── STEP 1: Compute raw request rate (req/min) ───────────────────────
    const elapsedMin   = Math.max(windowMs / 60000, 1 / 60);
    const requestRate  = requestCount / elapsedMin;

    // ── STEP 2: Normalize features to [0, 1] ────────────────────────────
    const x1_norm = minMaxNormalize(requestRate, hp.NORM_REQUEST_RATE.min, hp.NORM_REQUEST_RATE.max);
    const x2_norm = minMaxNormalize(threatCount, hp.NORM_THREAT_COUNT.min, hp.NORM_THREAT_COUNT.max);

    // ── STEP 3: Linear combination (weighted sum) ────────────────────────
    //   z = w1 · x1_norm + w2 · x2_norm + bias
    const w1 = hp.WEIGHTS[0];
    const w2 = hp.WEIGHTS[1];
    const z  = w1 * x1_norm + w2 * x2_norm + hp.BIAS;

    // ── STEP 4: Sigmoid activation → P(THREAT) ─────────────────────────
    const probability = sigmoid(z);

    // ── STEP 5: Apply classification threshold ───────────────────────────
    const isThreat = probability >= hp.THRESHOLD;
    const label    = isThreat ? hp.THREAT_LABEL : hp.NORMAL_LABEL;

    // Confidence: how far the probability is from the 0.5 boundary (0–1 scale)
    const confidence = parseFloat((Math.abs(probability - 0.5) * 2).toFixed(3));

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
        ? `LR: P(THREAT)=${(probability*100).toFixed(1)}% ≥ 50% threshold` +
          ` | rate=${requestRate.toFixed(1)} req/min, strikes=${threatCount}`
        : `LR: P(THREAT)=${(probability*100).toFixed(1)}% < 50% threshold` +
          ` | rate=${requestRate.toFixed(1)} req/min — classified NORMAL`,
      modelUsed:   ML_MODEL_1.algorithm,
    };
  },
};

// ════════════════════════════════════════════════════════════════════════════
// ML MODEL 2 — 3-Strike Auto-Ban Classifier (unchanged)
// Uses Model 1's output label as its input vote.
// ════════════════════════════════════════════════════════════════════════════

const ML_MODEL_2 = {
  name:        '3-Strike Auto-Ban Classifier',
  algorithm:   'Accumulative Strike Committee (Ensemble)',
  description: 'Acts on the output of Model 1. Each THREAT label from Model 1 ' +
               'counts as one committee vote. After 3 votes the IP is permanently ' +
               'banned — analogous to a k=3 ensemble majority vote classifier.',
  version:     '2.0.0',

  hyperparams: {
    BAN_STRIKES:  3,
    THREAT_LABEL: 'THREAT',
    BAN_LABEL:    'BANNED',
  },

  /**
   * predict(features) → { label, confidence, features, reason, action }
   *
   * @param {object} features
   *   @param {number} features.threatStrikes   - accumulated Model 1 THREAT votes
   *   @param {string} features.model1Decision  - current Model 1 label
   *   @param {string} features.currentStatus   - current DB status
   */
  predict(features) {
    const { BAN_STRIKES, THREAT_LABEL, BAN_LABEL } = ML_MODEL_2.hyperparams;
    const { threatStrikes, model1Decision, currentStatus } = features;

    if (currentStatus === 'BANNED') {
      return {
        label:      BAN_LABEL,
        confidence: 1.0,
        features,
        reason:     `IP already permanently banned (${threatStrikes} strikes).`,
        action:     'NONE',
      };
    }

    if (model1Decision === THREAT_LABEL) {
      const newStrikes = threatStrikes + 1;
      const shouldBan  = newStrikes >= BAN_STRIKES;

      return {
        label:      shouldBan ? BAN_LABEL : THREAT_LABEL,
        confidence: shouldBan ? 1.0 : parseFloat((newStrikes / BAN_STRIKES).toFixed(3)),
        features: {
          previousStrikes: threatStrikes,
          newStrikes,
          banThreshold:    BAN_STRIKES,
          votesRemaining:  Math.max(0, BAN_STRIKES - newStrikes),
        },
        reason: shouldBan
          ? `Strike ${newStrikes}/${BAN_STRIKES} — committee threshold reached. AUTO-BAN triggered.`
          : `Strike ${newStrikes}/${BAN_STRIKES} — accumulating evidence (${BAN_STRIKES - newStrikes} more to ban).`,
        action: shouldBan ? 'BAN_IP' : 'FLAG_THREAT',
      };
    }

    return {
      label:      currentStatus || 'NORMAL',
      confidence: 1.0,
      features:   { strikes: threatStrikes, banThreshold: BAN_STRIKES },
      reason:     'Model 1 classified NORMAL — no action required by Model 2.',
      action:     'NONE',
    };
  },
};

// ════════════════════════════════════════════════════════════════════════════
// ML PIPELINE — Runs both models in sequence on a DB ip_tracker record
// ════════════════════════════════════════════════════════════════════════════

/**
 * runMLPipeline(ipRecord, now) → { ip, model1, model2, finalDecision, timestamp }
 *
 * Orchestrates the two-model classification pipeline:
 *   Model 1 → rate-based logistic regression prediction
 *   Model 2 → strike committee decision based on Model 1's output
 */
function runMLPipeline(ipRecord, now = Date.now()) {
  const windowStart = new Date(ipRecord.window_start).getTime();
  const windowMs    = Math.max(now - windowStart, 0);

  // ── Stage 1: Logistic Regression (Model 1) ───────────────────────────
  const model1Result = ML_MODEL_1.predict({
    requestCount:  ipRecord.request_count || 0,
    windowMs,
    threatCount:   ipRecord.threat_count  || 0,
    currentStatus: ipRecord.status        || 'NORMAL',
  });

  // ── Stage 2: Strike Committee (Model 2 uses Model 1's label) ────────
  const model2Result = ML_MODEL_2.predict({
    threatStrikes:  ipRecord.threat_count || 0,
    model1Decision: model1Result.label,
    currentStatus:  ipRecord.status       || 'NORMAL',
  });

  // Final decision = strictest label from either model
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

// ════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ════════════════════════════════════════════════════════════════════════════

module.exports = {
  ML_MODEL_1,
  ML_MODEL_2,
  runMLPipeline,

  // Metadata for the /api/ml/status endpoint
  MODEL_METADATA: {
    model1: {
      name:        ML_MODEL_1.name,
      algorithm:   ML_MODEL_1.algorithm,
      description: ML_MODEL_1.description,
      version:     ML_MODEL_1.version,
      hyperparams: {
        weights:   SAVED_MODEL.weights,
        bias:      SAVED_MODEL.bias,
        threshold: SAVED_MODEL.classificationThreshold,
        norm:      SAVED_MODEL.norm,
      },
      metrics: SAVED_MODEL.metrics,
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
