const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../db/database');

// ============================================================
// SECURE ADMIN AUTHENTICATION (parameterized queries only)
// ============================================================

// POST /admin/login
router.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    // Parameterized query — NOT vulnerable
    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);

    if (!admin) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    const match = bcrypt.compareSync(password, admin.password);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    // Set secure session
    req.session.admin = {
      id: admin.id,
      username: admin.username,
      org: admin.org,
      loggedInAt: new Date().toISOString()
    };

    return res.json({
      success: true,
      message: 'Login successful.',
      admin: { username: admin.username, org: admin.org }
    });
  } catch (err) {
    console.error('[Auth] Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /admin/logout
router.post('/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: 'Logged out.' });
  });
});

// GET /admin/me — check session
router.get('/admin/me', (req, res) => {
  if (!req.session.admin) {
    return res.status(401).json({ authenticated: false });
  }
  res.json({ authenticated: true, admin: req.session.admin });
});

module.exports = router;
