// Builds the Express app: security checks first, then the API, then the React website.
const path = require('path');
const express = require('express');
const {
  securityHeaders,
  apiRateLimit,
  checkOrigin,
  rejectOperatorKeys,
  requireCloudflare,
  logVisitorIp,
} = require('./middleware/security');
const { apiNotFound, errorHandler } = require('./middleware/errors');
const { readClerkSession } = require('./middleware/auth');
const meRoutes = require('./routes/me');

const app = express();

// Don't tell visitors we run Express (one less hint for attackers)
app.disable('x-powered-by');

// 🔒 SECURITY 7.2.4 — Rate limit counts the real visitor, not Cloudflare (OWASP A04)
// In production every request passes proxies first (Cloudflare, then Render), and each one
// adds the address it came from to the "X-Forwarded-For" header. TRUST_PROXY_HOPS says how many
// of those proxies are ours; Express then takes req.ip from the right place in that list.
// Too low: everyone looks like Cloudflare and shares one rate limit. Too high: an attacker
// can fake their IP. The right number is proven with the IP check (SETUP_GUIDE 7.10).
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS || 0));

// Security headers on every response, including the React pages
app.use(securityHeaders);

// Health check for Render and the uptime monitor: just "ok", no details (D25).
// It sits above the Cloudflare check, because Render calls it directly.
app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

// Temporary IP check while TRUST_PROXY_HOPS is being verified (off unless LOG_IP_CHECK=true)
app.use(logVisitorIp);

// Everything below (API and website) only answers requests that came through Cloudflare
app.use(requireCloudflare);

// --- API: every request passes these checks, in this order ---
app.use('/api', apiRateLimit);
app.use('/api', checkOrigin);
// Read JSON bodies, max 100 KB (PDF uploads get their own limit in Phase 7)
app.use('/api', express.json({ limit: '100kb' }));
app.use('/api', rejectOperatorKeys);
// Read the Clerk session token (each route then decides if sign-in is required)
app.use('/api', readClerkSession);

// --- API routes ---
app.use('/api/me', meRoutes);

// Any /api address that doesn't exist
app.use('/api', apiNotFound);

// --- React website ---
// Folder that holds the built React app (created by `npm run build`)
const clientBuildFolder = path.join(__dirname, '..', 'client', 'dist');

// Serve the React files (JavaScript, CSS, images) as static files
app.use(express.static(clientBuildFolder));

// Send the React page for any other GET request, so React can show the right screen
app.use((req, res, next) => {
  if (req.method !== 'GET') {
    return next();
  }
  res.sendFile(path.join(clientBuildFolder, 'index.html'));
});

// Last: turn every error into a generic message (must be added after all routes)
app.use(errorHandler);

module.exports = app;
