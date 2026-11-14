// Admin: read the audit log. There is only a GET route: nobody can edit or delete entries.
const express = require('express');
const { AuditLog } = require('../models');
const { requireSignIn, requireRole } = require('../middleware/auth');

const router = express.Router();

// 🔒 SECURITY 7.6.1 — Audit log is read-only and admins only (OWASP A01, A09)
router.use(requireSignIn, requireRole('admin'));

// GET /api/audit-logs: the newest 200 entries, with the name and email of who did each one
router.get('/', async (req, res) => {
  const entries = await AuditLog.find()
    .sort({ at: -1 })
    .limit(200)
    .populate('actorId', 'name email');

  res.json(entries.map((entry) => ({
    id: entry.id,
    at: entry.at,
    actor: entry.actorId ? `${entry.actorId.name} (${entry.actorId.email})` : 'Unknown user',
    action: entry.action,
    target: entry.target,
    before: entry.before,
    after: entry.after,
  })));
});

module.exports = router;
