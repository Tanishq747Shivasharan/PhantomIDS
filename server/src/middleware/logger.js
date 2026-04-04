'use strict';

const fs   = require('fs');
const path = require('path');

const logFile = path.join(__dirname, '..', '..', 'logs', 'requests.log');
const logDir  = path.dirname(logFile);

if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

function logger(req, res, next) {
  const entry = `[${new Date().toISOString()}] ${req.ip} ${req.method} ${req.originalUrl} | UA: ${req.headers['user-agent'] || 'unknown'} | BODY: ${JSON.stringify(req.body) || '{}'}\n`;
  fs.appendFile(logFile, entry, (err) => {
    if (err) console.error('[Logger] Failed to write log:', err.message);
  });
  next();
}

module.exports = logger;
