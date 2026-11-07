// UniLearn server: connects to the database, then starts answering requests.
const app = require('./app');
const { connectToDatabase } = require('./db');
const { logInfo, logError } = require('./logger');

const PORT = process.env.PORT || 3000;

// Connect to Atlas first, so the site never runs without its database
async function startServer() {
  // In production the Cloudflare secret must be set, or every visitor would get 403 (D25)
  if (process.env.NODE_ENV === 'production' && !process.env.ORIGIN_SECRET) {
    throw new Error('ORIGIN_SECRET is missing. Add it in Render → Environment (see SETUP_GUIDE 6.3).');
  }
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
