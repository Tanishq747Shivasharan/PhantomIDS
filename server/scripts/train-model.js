#!/usr/bin/env node
/**
 * PhantomIDS — Logistic Regression Training Pipeline
 * ====================================================
 * This script trains ML Model 1 (Behavioural Anomaly Detector)
 * using Logistic Regression implemented from scratch.
 *
 * ALGORITHM: Binary Logistic Regression
 *   P(THREAT | features) = sigmoid(w1*x1 + w2*x2 + bias)
 *
 * TRAINING:  Gradient Descent (Binary Cross-Entropy Loss)
 *
 * INPUT:     data/training_data.csv
 *             → request_rate, threat_count, label
 *
 * OUTPUT:    src/ml/model.json
 *             → { weights: [w1, w2], bias, norm, accuracy }
 *
 * Usage:
 *   node scripts/train-model.js
 *   node scripts/train-model.js --epochs 2000 --lr 0.1
 */

'use strict';

const fs   = require('fs');
const path = require('path');

// ── Parse CLI arguments ─────────────────────────────────────────────────────
const args      = process.argv.slice(2);
const getArg    = (flag, def) => { const i = args.indexOf(flag); return i !== -1 ? +args[i+1] : def; };
const EPOCHS    = getArg('--epochs', 3000);    // gradient descent iterations
const LR        = getArg('--lr', 0.05);        // learning rate

const DATA_FILE  = path.join(__dirname, '../data/training_data.csv');
const MODEL_FILE = path.join(__dirname, '../src/ml/model.json');

// ════════════════════════════════════════════════════════════════════════════
// STEP 1 — LOAD AND PARSE THE TRAINING DATA
// ════════════════════════════════════════════════════════════════════════════

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║    PhantomIDS — Model 1 Training Pipeline            ║');
console.log('║    Algorithm: Logistic Regression (Gradient Descent) ║');
console.log('╚══════════════════════════════════════════════════════╝\n');

console.log('[1/5] Loading training data from:', DATA_FILE);

const raw = fs.readFileSync(DATA_FILE, 'utf8');
const lines = raw.trim().split('\n').filter(l => !l.startsWith('request_rate'));

// Each sample: { x: [request_rate, threat_count], y: 0 or 1 }
const dataset = lines.map(line => {
  const [req_rate, threat_count, label] = line.trim().split(',');
  return {
    x: [parseFloat(req_rate), parseFloat(threat_count)],
    y: label.trim().toUpperCase() === 'THREAT' ? 1 : 0,
  };
});

const normal = dataset.filter(d => d.y === 0).length;
const threat = dataset.filter(d => d.y === 1).length;
console.log(`   ✓ Loaded ${dataset.length} samples  [NORMAL: ${normal}  THREAT: ${threat}]\n`);

// ════════════════════════════════════════════════════════════════════════════
// STEP 2 — FEATURE NORMALIZATION (min-max scaling)
//
// Why? Gradient descent converges faster when features are in [0, 1].
// We normalize request_rate and threat_count separately.
// The normalization params (min, max) are saved to model.json so the
// same transformation is applied at prediction time.
// ════════════════════════════════════════════════════════════════════════════

console.log('[2/5] Normalizing features (min-max scaling)...');

function columnStats(data, col) {
  const vals = data.map(d => d.x[col]);
  return { min: Math.min(...vals), max: Math.max(...vals) };
}

const statsRate   = columnStats(dataset, 0);
const statsStrike = columnStats(dataset, 1);

// Avoid division by zero
const rangeRate   = statsRate.max   - statsRate.min   || 1;
const rangeStrike = statsStrike.max - statsStrike.min || 1;

function normalize(x0, x1) {
  return [
    (x0 - statsRate.min)   / rangeRate,
    (x1 - statsStrike.min) / rangeStrike,
  ];
}

const normalized = dataset.map(d => ({
  x: normalize(d.x[0], d.x[1]),
  y: d.y,
}));

console.log(`   ✓ request_rate  → [${statsRate.min}, ${statsRate.max}]`);
console.log(`   ✓ threat_count  → [${statsStrike.min}, ${statsStrike.max}]\n`);

// ════════════════════════════════════════════════════════════════════════════
// STEP 3 — LOGISTIC REGRESSION CORE FUNCTIONS
//
// sigmoid(z) = 1 / (1 + e^-z)
//   Maps any real number to (0, 1) — we interpret this as P(THREAT).
//
// predict(x, w, b) → probability ∈ [0, 1]
//   z = w[0]*x[0] + w[1]*x[1] + b
//   P(THREAT) = sigmoid(z)
//
// binaryCrossEntropy(y, p) → scalar loss
//   The standard loss function for binary classification.
//   J = -[y*log(p) + (1-y)*log(1-p)]
// ════════════════════════════════════════════════════════════════════════════

const sigmoid = z => 1 / (1 + Math.exp(-z));

function forwardPass(x, w, b) {
  const z = w[0] * x[0] + w[1] * x[1] + b;
  return sigmoid(z);
}

function computeLoss(data, w, b) {
  const eps = 1e-12; // avoids log(0)
  let loss = 0;
  for (const { x, y } of data) {
    const p = forwardPass(x, w, b);
    loss += -(y * Math.log(p + eps) + (1 - y) * Math.log(1 - p + eps));
  }
  return loss / data.length;
}

// ════════════════════════════════════════════════════════════════════════════
// STEP 4 — GRADIENT DESCENT TRAINING
//
// Each iteration:
//   For every sample (x, y):
//     error = P(THREAT) - y         ← prediction error
//     dw[j] += error * x[j]         ← gradient for weight j
//     db    += error                 ← gradient for bias
//
//   Update weights:
//     w[j] -= lr * (1/N) * dw[j]
//     b    -= lr * (1/N) * db
//
// This minimizes the cross-entropy loss iteratively.
// ════════════════════════════════════════════════════════════════════════════

console.log(`[3/5] Training Logistic Regression...`);
console.log(`   Epochs: ${EPOCHS}  |  Learning Rate: ${LR}\n`);

// Initialize weights and bias to zero (standard starting point)
let w = [0.0, 0.0];
let b = 0.0;
const N = normalized.length;
const logInterval = Math.floor(EPOCHS / 5);

for (let epoch = 0; epoch <= EPOCHS; epoch++) {
  let dw = [0, 0];
  let db = 0;

  // Compute gradients over all samples
  for (const { x, y } of normalized) {
    const p     = forwardPass(x, w, b);
    const error = p - y;
    dw[0] += error * x[0];
    dw[1] += error * x[1];
    db    += error;
  }

  // Update parameters
  w[0] -= LR * (dw[0] / N);
  w[1] -= LR * (dw[1] / N);
  b    -= LR * (db    / N);

  if (epoch % logInterval === 0) {
    const loss = computeLoss(normalized, w, b);
    process.stdout.write(`   Epoch ${String(epoch).padStart(5)} / ${EPOCHS}  →  Loss: ${loss.toFixed(6)}\n`);
  }
}

// ════════════════════════════════════════════════════════════════════════════
// STEP 5 — EVALUATE MODEL ACCURACY
// ════════════════════════════════════════════════════════════════════════════

console.log('\n[4/5] Evaluating model on training data...');

let correct = 0;
let tp = 0, fp = 0, fn = 0, tn = 0;

for (const { x, y } of normalized) {
  const prob = forwardPass(x, w, b);
  const pred = prob >= 0.5 ? 1 : 0;
  if (pred === y) correct++;
  if (pred === 1 && y === 1) tp++;
  if (pred === 1 && y === 0) fp++;
  if (pred === 0 && y === 1) fn++;
  if (pred === 0 && y === 0) tn++;
}

const accuracy  = (correct / N * 100).toFixed(2);
const precision = tp / (tp + fp + 1e-9);
const recall    = tp / (tp + fn + 1e-9);
const f1        = 2 * precision * recall / (precision + recall + 1e-9);

console.log(`   ✓ Accuracy : ${accuracy}%`);
console.log(`   ✓ Precision: ${(precision * 100).toFixed(2)}%`);
console.log(`   ✓ Recall   : ${(recall    * 100).toFixed(2)}%`);
console.log(`   ✓ F1 Score : ${(f1        * 100).toFixed(2)}%`);

// ════════════════════════════════════════════════════════════════════════════
// STEP 6 — SAVE MODEL TO model.json
//
// The saved file contains:
//   weights  → [w1, w2]   (one per feature)
//   bias     → b
//   norm     → normalization bounds (to reproduce exact same scaling)
//   metrics  → accuracy, F1, etc. (for display on dashboard)
// ════════════════════════════════════════════════════════════════════════════

console.log('\n[5/5] Saving model to:', MODEL_FILE);

const model = {
  algorithm:   'Logistic Regression (Binary Cross-Entropy, Gradient Descent)',
  version:     '2.0.0',
  trainedAt:   new Date().toISOString(),
  epochs:      EPOCHS,
  learningRate: LR,
  trainingSamples: N,

  // ── Model Parameters ────────────────────────────────────────────────────
  weights: [
    parseFloat(w[0].toFixed(6)),   // w1: coefficient for request_rate_normalized
    parseFloat(w[1].toFixed(6)),   // w2: coefficient for threat_count_normalized
  ],
  bias: parseFloat(b.toFixed(6)),

  // ── Normalization bounds (MUST match training data) ─────────────────────
  norm: {
    requestRate:  { min: statsRate.min,   max: statsRate.max   },
    threatCount:  { min: statsStrike.min, max: statsStrike.max },
  },

  // ── Performance metrics ─────────────────────────────────────────────────
  metrics: {
    accuracy:  parseFloat(accuracy),
    precision: parseFloat((precision * 100).toFixed(2)),
    recall:    parseFloat((recall    * 100).toFixed(2)),
    f1:        parseFloat((f1        * 100).toFixed(2)),
  },

  // ── Decision boundary ───────────────────────────────────────────────────
  classificationThreshold: 0.5,
  labels: { 0: 'NORMAL', 1: 'THREAT' },
};

fs.writeFileSync(MODEL_FILE, JSON.stringify(model, null, 2));
console.log(`   ✓ Saved!\n`);

console.log('╔══════════════════════════════════════════════════════╗');
console.log('║                Training Complete!                    ║');
console.log(`║  Accuracy : ${String(accuracy + '%').padEnd(10)}                          ║`);
console.log(`║  Weights  : w1=${w[0].toFixed(3)}  w2=${w[1].toFixed(3)}  bias=${b.toFixed(3)}     ║`);
console.log('╠══════════════════════════════════════════════════════╣');
console.log('║  Restart the server to load the new model:           ║');
console.log('║    npm start                                          ║');
console.log('╚══════════════════════════════════════════════════════╝\n');
