// Admin: list users, invite users, change roles, disable and re-enable accounts.
const express = require('express');
const { clerkClient } = require('@clerk/express');
const { User } = require('../models');
const { requireSignIn, requireRole } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { writeAuditLog } = require('../audit');
const { logInfo, logWarning } = require('../logger');

const router = express.Router();

// 🔒 SECURITY 7.2.1 / 7.2.2 — Every route in this file: signed in, then admin only (OWASP A01, A07)
router.use(requireSignIn, requireRole('admin'));

// Email domains that may be invited, from ALLOWED_EMAIL_DOMAIN in .env (comma-separated, D23).
// Empty list = nobody can be invited (fails closed if the setting is missing).
const allowedEmailDomains = (process.env.ALLOWED_EMAIL_DOMAIN || '')
  .split(',')
  .map((domain) => domain.trim().toLowerCase())
  .filter((domain) => domain !== '');

// True if the email looks like "something@domain" and the domain is on the allowed list
function isAllowedEmail(email) {
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    return false;
  }
  const domain = email.split('@')[1].toLowerCase();
  return allowedEmailDomains.includes(domain);
}

// Only the fields the admin page shows (no Clerk ID, no internal fields)
function toPublicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    studentNumber: user.studentNumber,
    hasSignedUp: Boolean(user.clerkId),
    createdAt: user.createdAt,
  };
}

// Find the user named in the address (/api/users/:id), refusing changes to the admin's own account
async function findOtherUser(req, res) {
  // An admin can't change their own role or disable themselves, so the last admin can't lock everyone out
  if (req.params.id === req.user.id) {
    res.status(400).json({ error: 'You cannot change your own account.' });
    return null;
  }
  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404).json({ error: 'Not found' });
    return null;
  }
  return user;
}

// GET /api/users: everyone, newest first
router.get('/', async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json(users.map(toPublicUser));
});

// POST /api/users: save a new user and send them a Clerk invitation email
router.post('/', allowFields('name', 'email', 'role', 'studentNumber'), async (req, res) => {
  const { name, role, studentNumber } = req.body;
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';

  // 🔒 SECURITY 7.5.4 — Invitations only go to university email addresses (OWASP A07, D23)
  // Checked here, before Clerk is called, so a wrong address never gets an invitation.
  if (!isAllowedEmail(email)) {
    logWarning('Invitation refused: email domain not allowed', { actorId: req.user.id, email });
    return res.status(400).json({ error: 'Only university email addresses can be invited.' });
  }
  if (await User.exists({ email })) {
    return res.status(409).json({ error: 'A user with this email already exists.' });
  }

  // Mongoose checks name, role (only the three roles) and lengths; unknown fields were refused above
  const user = await User.create({
    name,
    email,
    role,
    studentNumber: role === 'student' ? studentNumber : undefined,
  });

  try {
    // 🔒 SECURITY 7.5.4 — No public sign-up: people join only through an invitation (OWASP A07)
    await clerkClient.invitations.createInvitation({
      emailAddress: user.email,
      redirectUrl: process.env.APP_URL || 'http://localhost:5173',
    });
  } catch (err) {
    // If Clerk refused, don't leave a half-created user behind
    await user.deleteOne();
    throw err;
  }

  await writeAuditLog(req.user, 'account.create', `users/${user.id}`, null, { email: user.email, role: user.role });
  logInfo('User invited', { actorId: req.user.id, userId: user.id, role: user.role });
  res.status(201).json(toPublicUser(user));
});

// PATCH /api/users/:id/role: give a user another role
router.patch('/:id/role', allowFields('role'), async (req, res) => {
  const user = await findOtherUser(req, res);
  if (!user) {
    return;
  }
  const oldRole = user.role;
  if (req.body.role === oldRole) {
    return res.json(toPublicUser(user));
  }
  user.role = req.body.role;
  // Mongoose refuses any role that isn't admin, instructor or student (400)
  await user.save();

  // 🔒 SECURITY 7.6.1 — Role changes are audit-logged with the old and new role (OWASP A09)
  await writeAuditLog(req.user, 'role.change', `users/${user.id}`, { role: oldRole }, { role: user.role });
  res.json(toPublicUser(user));
});

// PATCH /api/users/:id/status: disable an account (person left) or enable it again
router.patch('/:id/status', allowFields('status'), async (req, res) => {
  const user = await findOtherUser(req, res);
  if (!user) {
    return;
  }
  const oldStatus = user.status;
  if (req.body.status === oldStatus) {
    return res.json(toPublicUser(user));
  }
  user.status = req.body.status;
  // Mongoose refuses any status that isn't active or disabled (400)
  await user.save();
  await writeAuditLog(req.user, `account.${user.status === 'active' ? 'enable' : 'disable'}`,
    `users/${user.id}`, { status: oldStatus }, { status: user.status });

  // 🔒 SECURITY 7.5.5 — Disabled accounts are also banned in Clerk (OWASP A01)
  // Two locks: our server refuses disabled users on every call (middleware/auth.js), and the
  // Clerk ban ends their sessions at once and stops them signing in at all.
  // Users who haven't signed up yet have no Clerk account; our server lock is enough for them.
  if (user.clerkId) {
    if (user.status === 'disabled') {
      await clerkClient.users.banUser(user.clerkId);
    } else {
      await clerkClient.users.unbanUser(user.clerkId);
    }
  }
  res.json(toPublicUser(user));
});

module.exports = router;
