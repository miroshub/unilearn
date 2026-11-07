// App logger: prints one line per event. Render keeps these lines as the application log.

// 🔒 SECURITY 7.6.6 — Logs never contain passwords or tokens (OWASP A09)
// Any detail whose name looks secret is replaced before it is printed.
const SECRET_NAMES = /pass|token|secret|authorization|cookie|key|uri/i;

// Replace secret values in a details object with "[hidden]"
function hideSecrets(details) {
  const safe = {};
  for (const [name, value] of Object.entries(details)) {
    if (SECRET_NAMES.test(name)) {
      safe[name] = '[hidden]';
    } else if (typeof value === 'string') {
      // Hide the "user:password@" part of any connection string
      safe[name] = value.replace(/\/\/[^/\s@]+@/g, '//[hidden]@');
    } else {
      safe[name] = value;
    }
  }
  return safe;
}

// Print one log line: time, level, message and the (cleaned) details
function writeLog(level, message, details = {}) {
  const line = `${new Date().toISOString()} ${level} ${message} ${JSON.stringify(hideSecrets(details))}`;
  if (level === 'ERROR') {
    console.error(line);
  } else {
    console.log(line);
  }
}

// Normal events, like "server started"
function logInfo(message, details) {
  writeLog('INFO', message, details);
}

// 🔒 SECURITY 7.6.2 — Application log: denied access and blocked requests (OWASP A09)
// These WARN lines (and ERROR lines) are the ones to review weekly in Render's logs.
function logWarning(message, details) {
  writeLog('WARN', message, details);
}

// Unexpected errors, with the full detail kept out of the user's reply
function logError(message, details) {
  writeLog('ERROR', message, details);
}

module.exports = { logInfo, logWarning, logError, hideSecrets };
