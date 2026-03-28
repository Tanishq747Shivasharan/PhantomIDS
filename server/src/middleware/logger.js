const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, '..', '..', 'logs', 'requests.log');

// Ensure logs directory exists
const logDir = path.dirname(logFile);
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

function logger(req, res, next) {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const method = req.method;
  const url = req.originalUrl;
  const userAgent = req.headers['user-agent'] || 'unknown';
  const body = JSON.stringify(req.body) || '{}';

  const logEntry = `[${timestamp}] ${ip} ${method} ${url} | UA: ${userAgent} | BODY: ${body}\n`;

  fs.appendFile(logFile, logEntry, (err) => {
    if (err) console.error('[Logger] Failed to write log:', err.message);
  });

  next();
}

module.exports = logger;
