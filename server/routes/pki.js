// UniLearn's public certificates (/api/pki), so the browser can check signatures itself (DECISIONS D40).
const express = require('express');
const { requireSignIn, requireRole } = require('../middleware/auth');
const { publicCertificateInfo } = require('../pki');

const router = express.Router();

// 🔒 SECURITY 7.2.1 — Signed-in users only, like every API route (OWASP A07)
// Certificates and public keys are public by design; they contain no secrets.
router.get('/', requireSignIn, requireRole('admin', 'instructor', 'student'), (req, res) => {
  res.json(publicCertificateInfo());
});

module.exports = router;
