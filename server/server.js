// UniLearn server: connects to the database, then starts answering requests.
const app = require('./app');
const { connectToDatabase } = require('./db');
const { logInfo, logError } = require('./logger');

const PORT = process.env.PORT || 3000;

// Connect to Atlas first, so the site never runs without its database
async function startServer() {
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
