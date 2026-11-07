// Security checks that run before any API route.
const crypto = require('crypto');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { logInfo, logWarning } = require('../logger');

// Clerk's address for this app, read from the publishable key.
// The key is "pk_test_" + base64("<name>.clerk.accounts.dev$"), so decoding it gives the address.
function getClerkAddress() {
  const encoded = (process.env.CLERK_PUBLISHABLE_KEY || '').split('_')[2] || '';
  const host = Buffer.from(encoded, 'base64').toString('utf8').replace('$', '');
  return host ? `https://${host}` : '';
}
// As a list, so it is simply left out when no key is set yet
const clerkAddress = getClerkAddress() ? [getClerkAddress()] : [];

// 🔒 SECURITY 7.2.5 — Standard security headers (OWASP A05)
// helmet adds headers like Content-Security-Policy (only load scripts from our own site)
// and X-Frame-Options (other sites can't put UniLearn in a frame = no clickjacking).
// The only outside site allowed is our own Clerk address, for the sign-in screens (DECISIONS D31).
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      'script-src': ["'self'", ...clerkAddress],
      'connect-src': ["'self'", ...clerkAddress],
      'img-src': ["'self'", 'data:', 'https://img.clerk.com'],
      'worker-src': ["'self'", 'blob:'],
      // Clerk's sign-in box sets its own styles at runtime, so inline styles must be allowed.
      // Inline *scripts* stay blocked, which is what stops XSS.
      'style-src': ["'self'", "'unsafe-inline'"],
    },
  },
});

// 🔒 SECURITY 7.2.4 — Limit on requests per minute (OWASP A04, A07)
// Each IP address gets 100 API calls per minute; after that it gets 429 "Too many requests".
const apiRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  // Log the blocked request (7.6.2) and send a short message
  handler: (req, res) => {
    logWarning('Rate limit hit', { ip: req.ip, method: req.method, path: req.baseUrl + req.path });
    res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
  },
});

// Websites allowed to call the API, from ALLOWED_ORIGINS in .env (comma-separated)
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim());

// 🔒 SECURITY 7.2.5 — API accepts calls only from the UniLearn website (OWASP A05)
// Browsers send an "Origin" header saying which website made the call.
// If another website tries to call our API, we refuse it before any route runs.
function checkOrigin(req, res, next) {
  const origin = req.get('Origin');
  if (origin && !allowedOrigins.includes(origin)) {
    logWarning('Blocked request from another website', { ip: req.ip, origin, path: req.baseUrl + req.path });
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// True if any key in the object (at any depth) starts with "$" or contains "."
function hasOperatorKey(value) {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  for (const key of Object.keys(value)) {
    if (key.startsWith('$') || key.includes('.')) {
      return true;
    }
    if (hasOperatorKey(value[key])) {
      return true;
    }
  }
  return false;
}

// 🔒 SECURITY 7.3.4 — Query filters cleaned: NoSQL injection blocked (OWASP A03)
// An attacker could send {"email": {"$ne": ""}} to turn a search into "match everyone".
// Normal users never send keys starting with "$", so any request containing one is refused.
function rejectOperatorKeys(req, res, next) {
  if (hasOperatorKey(req.body) || hasOperatorKey(req.query) || hasOperatorKey(req.params)) {
    logWarning('Blocked request with database operators', { ip: req.ip, path: req.baseUrl + req.path });
    return res.status(400).json({ error: 'Bad request' });
  }
  next();
}

// The secret Cloudflare adds to every request, plus the previous one while it is being changed (D25).
// trim() drops spaces or line breaks that sneak in when the value is pasted into Render.
const originSecrets = [process.env.ORIGIN_SECRET, process.env.ORIGIN_SECRET_OLD]
  .filter(Boolean)
  .map((secret) => secret.trim());

// True if the two texts are equal. Both are hashed first so they have the same length,
// then compared in constant time, so an attacker can't guess the secret one letter at a time.
function isSameSecret(sent, expected) {
  const sentHash = crypto.createHash('sha256').update(sent).digest();
  const expectedHash = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(sentHash, expectedHash);
}

// 🔒 SECURITY 7.4.1 — Only Cloudflare may reach the app, so nobody can skip the WAF (OWASP A05)
// Cloudflare adds a secret "X-Origin-Verify" header to every request it forwards (SETUP_GUIDE 7.8).
// A request that comes straight to Render has no such header, so it is refused.
// Only in production: on your PC there is no Cloudflare in front.
function requireCloudflare(req, res, next) {
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }
  const sent = req.get('X-Origin-Verify') || '';
  // With no secret configured, nothing matches, so every request is refused (fails closed)
  if (!originSecrets.some((secret) => isSameSecret(sent, secret))) {
    // Never log the header itself. Only whether it was there and its length, which tells
    // "came straight to Render" (no header) apart from "wrong secret" (header, but no match).
    logWarning('Blocked request that did not come through Cloudflare', {
      ip: req.ip,
      method: req.method,
      path: req.path,
      hadHeader: sent !== '',
      headerLength: sent.length,
    });
    return res.status(403).type('text/plain').send('Forbidden');
  }
  next();
}

// Temporary check for "trust proxy" (SETUP_GUIDE 7.10): logs which IP Express thinks the
// visitor has, next to the raw proxy headers, so we can prove req.ip is the real visitor.
// Only runs while LOG_IP_CHECK=true, because IP addresses are personal data.
function logVisitorIp(req, res, next) {
  if (process.env.LOG_IP_CHECK === 'true') {
    logInfo('IP check', {
      ip: req.ip,
      forwardedFor: req.get('X-Forwarded-For'),
      cloudflareIp: req.get('CF-Connecting-IP'),
      path: req.path,
    });
  }
  next();
}

module.exports = {
  securityHeaders,
  apiRateLimit,
  allowedOrigins,
  checkOrigin,
  rejectOperatorKeys,
  requireCloudflare,
  logVisitorIp,
};
