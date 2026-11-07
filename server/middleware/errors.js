// What the server answers when something goes wrong.
const { logWarning, logError } = require('../logger');

// Short, generic messages: they never mention files, fields or database details
const GENERIC_MESSAGES = {
  400: 'Bad request',
  401: 'Please sign in',
  403: 'Forbidden',
  404: 'Not found',
  413: 'The request is too large',
};

// Unknown API address: reply 404 in the same JSON shape as other errors
function apiNotFound(req, res) {
  logWarning('Unknown API route', { ip: req.ip, method: req.method, path: req.baseUrl + req.path });
  res.status(404).json({ error: GENERIC_MESSAGES[404] });
}

// Turn any error into a status code (bad input = 400, everything unexpected = 500)
function getStatusCode(err) {
  // Mongoose: wrong data shape, unknown field, or a malformed ID
  if (['ValidationError', 'StrictModeError', 'CastError'].includes(err.name)) {
    return 400;
  }
  // Express: broken JSON (400) or a body that's too big (413)
  if (err.status >= 400 && err.status < 500) {
    return err.status;
  }
  return 500;
}

// 🔒 SECURITY 7.2.7 — Users see a generic message; details go to the logs (OWASP A05)
// Express sends every error here. The full error (message + stack) is logged for us,
// and the user only gets a short message, so attackers learn nothing about our code.
function errorHandler(err, req, res, next) {
  const status = getStatusCode(err);
  const details = { ip: req.ip, method: req.method, path: req.baseUrl + req.path, error: err.message };

  if (status === 500) {
    logError('Unexpected error', { ...details, stack: err.stack });
  } else {
    logWarning('Request refused', { ...details, status });
  }

  res.status(status).json({ error: GENERIC_MESSAGES[status] || 'Something went wrong' });
}

module.exports = { apiNotFound, errorHandler };
