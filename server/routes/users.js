// Admin: list users, invite users, change roles, disable and re-enable accounts,
// and the GDPR actions: correct a name or email, anonymise someone who has left (D22).
const express = require('express');
const { clerkClient } = require('@clerk/express');
const { User, Submission } = require('../models');
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
    anonymised: Boolean(user.anonymisedAt),
    createdAt: user.createdAt,
  };
}

// Send a Clerk invitation email; after sign-up the person comes back to UniLearn
async function sendInvitation(email) {
  // 🔒 SECURITY 7.5.4 — No public sign-up: people join only through an invitation (OWASP A07)
  await clerkClient.invitations.createInvitation({
    emailAddress: email,
    redirectUrl: process.env.APP_URL || 'http://localhost:5173',
  });
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
  // An anonymised account is closed for good: no new role, no re-enabling, no new name
  if (user.anonymisedAt) {
    res.status(400).json({ error: 'This account is anonymised and cannot be changed.' });
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
    await sendInvitation(user.email);
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

// PATCH /api/users/:id/details: correct a wrong name or email (GDPR right to rectification, D22)
router.patch('/:id/details', allowFields('name', 'email'), async (req, res) => {
  const user = await findOtherUser(req, res);
  if (!user) {
    return;
  }
  const before = { name: user.name, email: user.email };
  if (req.body.name !== undefined) {
    user.name = req.body.name;
  }
  if (req.body.email !== undefined) {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    // 🔒 SECURITY 7.5.4 — A corrected email must still be a university address (OWASP A07, D23)
    if (!isAllowedEmail(email)) {
      return res.status(400).json({ error: 'Only university email addresses can be used.' });
    }
    if (email !== user.email && await User.exists({ email })) {
      return res.status(409).json({ error: 'A user with this email already exists.' });
    }
    user.email = email;
  }
  const after = { name: user.name, email: user.email };
  if (after.name === before.name && after.email === before.email) {
    return res.json(toPublicUser(user));
  }
  // Mongoose checks the name (required, max 100 characters)
  await user.save();

  // Not signed up yet: the old invitation went to the wrong address, so send one to the corrected address.
  // (Someone using the old invitation now gets "no UniLearn account", because no user has that email any more.)
  if (!user.clerkId && after.email !== before.email) {
    try {
      await sendInvitation(user.email);
    } catch (err) {
      // If Clerk refused, put the old email back, so the record matches the invitation that exists
      user.email = before.email;
      await user.save();
      throw err;
    }
  }

  // 🔒 SECURITY 7.6.1 — Corrections are audit-logged with the old and new values (OWASP A09, D22)
  await writeAuditLog(req.user, 'account.correct', `users/${user.id}`, before, after);
  res.json(toPublicUser(user));
});

// 🔒 SECURITY 7.3.5 — GDPR erasure: anonymise a person who has left (OWASP A02, D22)
// POST /api/users/:id/anonymise. Only for a DISABLED account (two deliberate steps, so no accident).
// Removed: the Clerk account (password, MFA, sessions), the person's PDFs, name, email, student number.
// Kept: grades and enrolments, now linked to "Anonymised user" (the university must keep academic records).
router.post('/:id/anonymise', async (req, res) => {
  const user = await findOtherUser(req, res);
  if (!user) {
    return;
  }
  if (user.status !== 'disabled') {
    return res.status(400).json({ error: 'Disable the account first, then anonymise it.' });
  }

  // 1) Delete the sign-in account in Clerk. "404" means it is already gone (for example on a retry).
  if (user.clerkId) {
    try {
      await clerkClient.users.deleteUser(user.clerkId);
    } catch (err) {
      if (err.status !== 404) {
        throw err;
      }
    }
  }
  // 2) Delete the person's submissions, with their PDFs
  const { deletedCount } = await Submission.deleteMany({ studentId: user._id });
  // 3) Replace every personal detail. ".invalid" is a reserved domain, so no email can ever reach it.
  user.name = 'Anonymised user';
  user.email = `anonymised-${user.id}@anonymised.invalid`;
  user.studentNumber = undefined;
  user.clerkId = undefined;
  user.anonymisedAt = new Date();
  await user.save();

  // 🔒 SECURITY 7.6.1 — Logged without the old name or email, so the log doesn't undo the erasure (OWASP A09)
  await writeAuditLog(req.user, 'account.anonymise', `users/${user.id}`,
    { status: 'disabled' }, { anonymised: true, submissionsRemoved: deletedCount });
  logInfo('Account anonymised', { actorId: req.user.id, userId: user.id });
  res.json(toPublicUser(user));
});

module.exports = router;
