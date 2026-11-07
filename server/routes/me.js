// "Who am I?" — tells the React app the signed-in user's name and role.
const express = require('express');
const { requireSignIn } = require('../middleware/auth');

const router = express.Router();

// GET /api/me: only the fields the page needs (never the whole user document)
router.get('/', requireSignIn, (req, res) => {
  res.json({ name: req.user.name, role: req.user.role });
});

module.exports = router;
