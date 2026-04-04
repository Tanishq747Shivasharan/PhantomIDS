'use strict';

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const db      = require('../db/database');

router.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);

    if (!admin || !bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }

    req.session.admin = {
      id:          admin.id,
      username:    admin.username,
      org:         admin.org,
      loggedInAt:  new Date().toISOString(),
    };

    return res.json({
      success: true,
      message: 'Login successful.',
      admin: { username: admin.username, org: admin.org },
    });
  } catch (err) {
    console.error('[Auth] Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

router.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true, message: 'Logged out.' }));
});

router.get('/admin/me', (req, res) => {
  if (!req.session.admin) {
    return res.status(401).json({ authenticated: false });
  }
  res.json({ authenticated: true, admin: req.session.admin });
});

module.exports = router;
