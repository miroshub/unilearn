// Connects the server to MongoDB Atlas and sets Mongoose's safety options.
const mongoose = require('mongoose');
const { logInfo } = require('./logger');

// Load every model, so Mongoose creates the 8 collections in Atlas at startup.
// (Each schema sets strict: 'throw' itself — see the 🔒 7.2.3 / 7.3.4 tag in models/.)
require('./models');

// Open the connection to Atlas, or stop with a clear message if it fails
async function connectToDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI is missing. Add it to server/.env (see SETUP_GUIDE Part 4).');
  }

  await mongoose.connect(uri, {
    // 🔒 SECURITY 7.3.2 — The app's DB user can only use this one database (OWASP A01)
    dbName: 'unilearn',
    // 🔒 SECURITY 7.3.3 — Encrypted connection to Atlas (OWASP A02)
    tls: true,
  });

  logInfo('DB connected', { database: mongoose.connection.name });
}

module.exports = { connectToDatabase };
