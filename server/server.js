'use strict';

const express = require('express');
const session = require('express-session');
const path    = require('path');
const os      = require('os');

const db             = require('./src/db/database');
const requestLogger  = require('./src/middleware/logger');
const threatDetector = require('./src/middleware/threatDetector');
const honeypotRoutes = require('./src/routes/honeypot');
const authRoutes     = require('./src/routes/auth');
const dashboardRoutes = require('./src/routes/dashboard');
const mlStatusRoutes  = require('./src/routes/mlStatus');

const app  = express();
const HOST = '0.0.0.0';
const PORT = 5000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'PhantomIDS-SecretKey-2024-xK9#mP!',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000,
  },
}));

app.use(requestLogger);
app.use(threatDetector);
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', honeypotRoutes);
app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', mlStatusRoutes);

app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/honeypot',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'honeypot.html')));
app.get('/login',     (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// Bait 404 response — mimics a real Apache server to keep scanners probing
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', server: 'Apache/2.4.41 (Ubuntu)' });
});

app.use((err, req, res, next) => {
  console.error('[Server Error]', err.message);
  res.status(500).json({ error: 'Internal Server Error' });
});

function getLanIP() {
  for (const iface of Object.values(os.networkInterfaces())) {
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
  console.log(`║  Local   : http://localhost:${PORT}                  ║`);
  console.log(`║  LAN     : http://${LAN}:${PORT}             ║`);
  console.log(`║  Login   : http://${LAN}:${PORT}/login        ║`);
  console.log(`║  Dashboard: http://${LAN}:${PORT}/dashboard   ║`);
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║  Creds   : phantom_admin / PhantomAdmin@2024     ║');
  console.log('╚══════════════════════════════════════════════════╝\n');
});

module.exports = app;
