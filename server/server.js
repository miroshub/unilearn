// UniLearn server: connects to the database, then starts answering requests.
const app = require('./app');
const { connectToDatabase } = require('./db');
const { logInfo, logError } = require('./logger');
const { getMasterKey } = require('./fileCrypto');
const { loadSigningIdentity } = require('./pki');

const PORT = process.env.PORT || 3000;

// Settings the server can't work without (in .env on your PC, in Render → Environment online)
const REQUIRED_SETTINGS = [
  'MONGODB_URI', 'CLERK_PUBLISHABLE_KEY', 'CLERK_SECRET_KEY', 'FILE_ENCRYPTION_KEY', 'SIGNING_PRIVATE_KEY',
];

// Connect to Atlas first, so the site never runs without its database
async function startServer() {
  // Stop at startup with a clear message, instead of failing later on every sign-in
  const missing = REQUIRED_SETTINGS.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing settings: ${missing.join(', ')}. Add them in .env or Render → Environment (SETUP_GUIDE 6.3).`);
  }
  // In production the Cloudflare secret must be set, or every visitor would get 403 (D25)
  if (process.env.NODE_ENV === 'production' && !process.env.ORIGIN_SECRET) {
    throw new Error('ORIGIN_SECRET is missing. Add it in Render → Environment (see SETUP_GUIDE 6.3).');
  }
  // The PDF master key must be exactly 256 bits, or no upload or download could work (D38)
  getMasterKey();
  // 🔒 SECURITY 7.3.9 — Check the certificate chain and the signing key before serving anyone (D40)
  const { signingCert } = loadSigningIdentity();
  logInfo('Signing certificate OK', { subject: signingCert.subject, issuer: signingCert.issuer, validTo: signingCert.validTo });
  await connectToDatabase();
  app.listen(PORT, () => {
    logInfo('UniLearn server running', { url: `http://localhost:${PORT}` });
  });
}

// If startup fails (for example a wrong MONGODB_URI), log why and stop
startServer().catch((err) => {
  logError('Server failed to start', { error: err.message });
  process.exit(1);
});
