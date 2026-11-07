// Security checks that run before any API route.
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { logWarning } = require('../logger');

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

module.exports = { securityHeaders, apiRateLimit, allowedOrigins, checkOrigin, rejectOperatorKeys };
