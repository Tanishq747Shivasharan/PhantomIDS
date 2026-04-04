#!/usr/bin/env node
/**
 * PhantomIDS — Logistic Regression Training Pipeline
 *
 * Trains ML Model 1 from scratch using binary logistic regression
 * with gradient descent (binary cross-entropy loss).
 *
 * Input:  data/training_data.csv  (request_rate, threat_count, label)
 * Output: src/ml/model.json       (weights, bias, norm bounds, metrics)
 *
 * Usage:
 *   npm run train
 *   node scripts/train-model.js --epochs 2000 --lr 0.1
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const args   = process.argv.slice(2);
const getArg = (flag, def) => { const i = args.indexOf(flag); return i !== -1 ? +args[i + 1] : def; };
const EPOCHS = getArg('--epochs', 3000);
const LR     = getArg('--lr', 0.05);

const DATA_FILE  = path.join(__dirname, '../data/training_data.csv');
const MODEL_FILE = path.join(__dirname, '../src/ml/model.json');

console.log('\n[1/5] Loading training data...');

const lines   = fs.readFileSync(DATA_FILE, 'utf8').trim().split('\n').filter(l => !l.startsWith('request_rate'));
const dataset = lines.map(line => {
  const [req_rate, threat_count, label] = line.trim().split(',');
  return {
    x: [parseFloat(req_rate), parseFloat(threat_count)],
    y: label.trim().toUpperCase() === 'THREAT' ? 1 : 0,
  };
});

const normal = dataset.filter(d => d.y === 0).length;
const threat = dataset.filter(d => d.y === 1).length;
console.log(`   ${dataset.length} samples  [NORMAL: ${normal}  THREAT: ${threat}]`);

console.log('\n[2/5] Normalizing features (min-max)...');

function colStats(data, col) {
  const vals = data.map(d => d.x[col]);
  return { min: Math.min(...vals), max: Math.max(...vals) };
}

const statsRate   = colStats(dataset, 0);
const statsStrike = colStats(dataset, 1);
const rangeRate   = statsRate.max   - statsRate.min   || 1;
const rangeStrike = statsStrike.max - statsStrike.min || 1;

const normalized = dataset.map(d => ({
  x: [
    (d.x[0] - statsRate.min)   / rangeRate,
    (d.x[1] - statsStrike.min) / rangeStrike,
  ],
  y: d.y,
}));

console.log(`   request_rate → [${statsRate.min}, ${statsRate.max}]`);
console.log(`   threat_count → [${statsStrike.min}, ${statsStrike.max}]`);

console.log(`\n[3/5] Training — epochs: ${EPOCHS}  lr: ${LR}`);

const sigmoid     = z => 1 / (1 + Math.exp(-z));
const forwardPass = (x, w, b) => sigmoid(w[0] * x[0] + w[1] * x[1] + b);

function computeLoss(data, w, b) {
  const eps = 1e-12;
  return data.reduce((sum, { x, y }) => {
    const p = forwardPass(x, w, b);
    return sum - (y * Math.log(p + eps) + (1 - y) * Math.log(1 - p + eps));
  }, 0) / data.length;
}

let w = [0.0, 0.0];
let b = 0.0;
const N           = normalized.length;
const logInterval = Math.floor(EPOCHS / 5);

for (let epoch = 0; epoch <= EPOCHS; epoch++) {
  let dw = [0, 0];
  let db = 0;

  for (const { x, y } of normalized) {
    const err = forwardPass(x, w, b) - y;
    dw[0] += err * x[0];
    dw[1] += err * x[1];
    db    += err;
  }

  w[0] -= LR * (dw[0] / N);
  w[1] -= LR * (dw[1] / N);
  b    -= LR * (db    / N);

  if (epoch % logInterval === 0) {
    console.log(`   Epoch ${String(epoch).padStart(5)} / ${EPOCHS}  loss: ${computeLoss(normalized, w, b).toFixed(6)}`);
  }
}

console.log('\n[4/5] Evaluating...');

let correct = 0, tp = 0, fp = 0, fn = 0;

for (const { x, y } of normalized) {
  const pred = forwardPass(x, w, b) >= 0.5 ? 1 : 0;
  if (pred === y) correct++;
  if (pred === 1 && y === 1) tp++;
  if (pred === 1 && y === 0) fp++;
  if (pred === 0 && y === 1) fn++;
}

const accuracy  = (correct / N * 100).toFixed(2);
const precision = tp / (tp + fp + 1e-9);
const recall    = tp / (tp + fn + 1e-9);
const f1        = 2 * precision * recall / (precision + recall + 1e-9);

console.log(`   Accuracy : ${accuracy}%`);
console.log(`   Precision: ${(precision * 100).toFixed(2)}%`);
console.log(`   Recall   : ${(recall    * 100).toFixed(2)}%`);
console.log(`   F1 Score : ${(f1        * 100).toFixed(2)}%`);

console.log('\n[5/5] Saving model...');

fs.writeFileSync(MODEL_FILE, JSON.stringify({
  algorithm:        'Logistic Regression (Binary Cross-Entropy, Gradient Descent)',
  version:          '2.0.0',
  trainedAt:        new Date().toISOString(),
  epochs:           EPOCHS,
  learningRate:     LR,
  trainingSamples:  N,
  weights:          [parseFloat(w[0].toFixed(6)), parseFloat(w[1].toFixed(6))],
  bias:             parseFloat(b.toFixed(6)),
  norm: {
    requestRate: { min: statsRate.min,   max: statsRate.max   },
    threatCount: { min: statsStrike.min, max: statsStrike.max },
  },
  metrics: {
    accuracy:  parseFloat(accuracy),
    precision: parseFloat((precision * 100).toFixed(2)),
    recall:    parseFloat((recall    * 100).toFixed(2)),
    f1:        parseFloat((f1        * 100).toFixed(2)),
  },
  classificationThreshold: 0.5,
  labels: { 0: 'NORMAL', 1: 'THREAT' },
}, null, 2));

console.log(`   Saved to ${MODEL_FILE}`);
console.log(`\n   w1=${w[0].toFixed(3)}  w2=${w[1].toFixed(3)}  bias=${b.toFixed(3)}  accuracy=${accuracy}%`);
console.log('\n   Restart the server to load the new model: npm start\n');
