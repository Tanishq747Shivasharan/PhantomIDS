const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

// ── Init DB first (creates tables + seeds data) ──────────────
const db = require('./src/db/database');

// ── Middleware ────────────────────────────────────────────────
const requestLogger = require('./src/middleware/logger');
const threatDetector = require('./src/middleware/threatDetector');

// ── Routes ────────────────────────────────────────────────────
const honeypotRoutes  = require('./src/routes/honeypot');
const authRoutes      = require('./src/routes/auth');
const dashboardRoutes = require('./src/routes/dashboard');

const app = express();

// ── Body Parsers ──────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Session ───────────────────────────────────────────────────
app.use(session({
  secret: 'PhantomIDS-SecretKey-2024-xK9#mP!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,        // set true if behind HTTPS
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000  // 8 hours
  }
}));

// ── Logging (flat-file) ───────────────────────────────────────
app.use(requestLogger);

// ── Threat Detection (3-Strikes per IP) ──────────────────────
app.use(threatDetector);

// ── Static Files ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Mount Routes ──────────────────────────────────────────────
app.use('/', honeypotRoutes);
app.use('/', authRoutes);
app.use('/', dashboardRoutes);

// ── SPA Fallback for HTML pages ───────────────────────────────
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/honeypot', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'honeypot.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ── 404 Fallback (return bait-like response for scanners) ─────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', server: 'Apache/2.4.41 (Ubuntu)' });
});

// ── Error Handler ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ error: 'Internal Server Error' });
});

// ── Start ─────────────────────────────────────────────────────
const HOST = '0.0.0.0';
const PORT = 5000;

// Detect local LAN IP dynamically
const os = require('os');
function getLanIP() {
  const nets = os.networkInterfaces();
  for (const iface of Object.values(nets)) {
    for (const net of iface) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return 'localhost';
}

app.listen(PORT, HOST, () => {
  const LAN = getLanIP();
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║          PhantomIDS — Node.js Server             ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log(`║  Local         : http://localhost:${PORT}            ║`);
  console.log(`║  LAN           : http://${LAN}:${PORT}         ║`);
  console.log(`║  Honeypot      : http://${LAN}:${PORT}/honeypot ║`);
  console.log(`║  Admin Login   : http://${LAN}:${PORT}/login    ║`);
  console.log(`║  Dashboard     : http://${LAN}:${PORT}/dashboard ║`);
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  Admin Creds  : phantom_admin / PhantomAdmin@2024 ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
});

module.exports = app;
