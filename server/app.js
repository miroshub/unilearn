// Builds the Express app: security checks first, then the API, then the React website.
const path = require('path');
const express = require('express');
const { securityHeaders, apiRateLimit, checkOrigin, rejectOperatorKeys } = require('./middleware/security');
const { apiNotFound, errorHandler } = require('./middleware/errors');

const app = express();

// Don't tell visitors we run Express (one less hint for attackers)
app.disable('x-powered-by');

// Security headers on every response, including the React pages
app.use(securityHeaders);

// Health check for Render and the uptime monitor: just "ok", no details (D25)
app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok');
});

// --- API: every request passes these checks, in this order ---
app.use('/api', apiRateLimit);
app.use('/api', checkOrigin);
// Read JSON bodies, max 100 KB (PDF uploads get their own limit in Phase 7)
app.use('/api', express.json({ limit: '100kb' }));
app.use('/api', rejectOperatorKeys);

// (API routes are added here in later phases)

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
