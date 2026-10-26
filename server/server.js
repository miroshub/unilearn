// UniLearn server: serves the API and the built React website from one place.
const path = require('path');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

// Folder that holds the built React app (created by `npm run build`)
const clientBuildFolder = path.join(__dirname, '..', 'client', 'dist');

// Serve the React files (JavaScript, CSS, images) as static files
app.use(express.static(clientBuildFolder));

// Send the React page for any other GET request, so React Router can show the right screen
app.use((req, res, next) => {
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    return next();
  }
  res.sendFile(path.join(clientBuildFolder, 'index.html'));
});

// Start listening for requests
app.listen(PORT, () => {
  console.log(`UniLearn server running on http://localhost:${PORT}`);
});
