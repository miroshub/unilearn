// Writes entries into the auditLogs collection (who did what, to what, before → after).
const { AuditLog } = require('./models');

// 🔒 SECURITY 7.6.1 — Audit log entry for a sensitive change (OWASP A09)
// Called by routes right after the change is saved. There is no route that edits or
// deletes audit entries, so nobody can hide what they did (repudiation).
async function writeAuditLog(actor, action, target, before, after) {
  await AuditLog.create({ actorId: actor._id, action, target, before, after });
}

module.exports = { writeAuditLog };
