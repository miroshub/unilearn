// 🔒 SECURITY 7.6.1 — Record of sensitive actions: who did what, to what, and when (OWASP A09)
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const auditLogSchema = new mongoose.Schema({
  // Who did it
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // What they did, for example "grade.change" or "role.change"
  action: { type: String, required: true, trim: true, maxlength: 50 },
  // What it was done to, for example "grades/6718a2f4c3b1e2a9d4f0a111"
  target: { type: String, required: true, trim: true, maxlength: 200 },
  // The values before and after the change (for a grade: the old and new score)
  before: { type: mongoose.Schema.Types.Mixed },
  after: { type: mongoose.Schema.Types.Mixed },
  at: { type: Date, default: Date.now },
}, { strict: 'throw', strictQuery: 'throw' });

// Newest entries first on the audit log page
auditLogSchema.index({ at: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema, 'auditLogs');
