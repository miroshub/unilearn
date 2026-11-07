// Sign-in checks: who is calling, do they have a UniLearn account, and may they use it?
const { clerkMiddleware, clerkClient, getAuth } = require('@clerk/express');
const { User } = require('../models');
const { allowedOrigins } = require('./security');
const { logInfo, logWarning } = require('../logger');

// 🔒 SECURITY 7.1.3 — Sessions handled by Clerk (OWASP A07)
// Reads the Clerk session token sent with each request and checks its signature.
// "authorizedParties" also rejects tokens that were issued to any other website.
const readClerkSession = clerkMiddleware({ authorizedParties: allowedOrigins });

// Reply with a refusal, and log it so denied access shows up in Render's logs (7.6.2)
function refuse(req, res, status, code, message) {
  logWarning('Access refused', { ip: req.ip, path: req.baseUrl + req.path, code });
  return res.status(status).json({ error: message, code });
}

// True if the user has a second factor (authenticator app) registered in Clerk.
// Clerk puts this in the session token: factorVerificationAge[1] is -1 when there is none.
function hasSecondFactor(auth) {
  return Array.isArray(auth.factorVerificationAge) && auth.factorVerificationAge[1] !== -1;
}

// First sign-in after an invitation: find the invited user by their verified email and save their Clerk ID
async function linkInvitedUser(clerkId) {
  const clerkUser = await clerkClient.users.getUser(clerkId);
  const primaryEmail = clerkUser.primaryEmailAddress;
  // Only trust an email address that Clerk has verified
  if (!primaryEmail || primaryEmail.verification?.status !== 'verified') {
    return null;
  }
  const user = await User.findOne({ email: primaryEmail.emailAddress.toLowerCase(), clerkId: { $exists: false } });
  if (!user) {
    return null;
  }
  user.clerkId = clerkId;
  await user.save();
  logInfo('Invited user linked to Clerk account', { userId: user.id });
  return user;
}

// 🔒 SECURITY 7.2.1 — Sign-in check on every API route (OWASP A07)
// Runs before any route that needs a user. Afterwards, req.user is the UniLearn user.
async function requireSignIn(req, res, next) {
  const auth = getAuth(req);
  if (!auth.isAuthenticated) {
    return refuse(req, res, 401, 'NOT_SIGNED_IN', 'Please sign in');
  }

  // Find this person in our users collection (roles live here, not in the browser)
  let user = await User.findOne({ clerkId: auth.userId });
  if (!user) {
    user = await linkInvitedUser(auth.userId);
  }
  // 🔒 SECURITY 7.5.4 — No public sign-up: only invited people have a UniLearn account (OWASP A07)
  if (!user) {
    return refuse(req, res, 403, 'NO_ACCOUNT', 'You do not have a UniLearn account. Ask an administrator for an invitation.');
  }

  // 🔒 SECURITY 7.5.5 — Disabled accounts are refused, even with a valid Clerk session (OWASP A01)
  if (user.status !== 'active') {
    return refuse(req, res, 403, 'ACCOUNT_DISABLED', 'This account is disabled.');
  }

  // 🔒 SECURITY 7.5.1 — MFA required for admins and instructors (OWASP A07)
  // Staff can change grades and accounts, so a stolen password alone must not be enough.
  if (user.role !== 'student' && !hasSecondFactor(auth)) {
    return refuse(req, res, 403, 'MFA_REQUIRED', 'Staff accounts must turn on two-step verification.');
  }

  req.user = user;
  next();
}

module.exports = { readClerkSession, requireSignIn };
