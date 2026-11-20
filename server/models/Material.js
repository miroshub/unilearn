// A course material PDF uploaded by the course's instructor (8th collection, DECISIONS D19).
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const materialSchema = new mongoose.Schema({
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  // The PDF, encrypted with AES-256-GCM (D38, see fileCrypto.js); not loaded in lists, only on download
  file: { type: Buffer, required: true, select: false },
  // SHA-256 fingerprint of the original PDF (64 hex characters)
  fileSha256: { type: String, required: true, match: /^[0-9a-f]{64}$/ },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  uploadedAt: { type: Date, default: Date.now },
}, { strict: 'throw', strictQuery: 'throw' });

module.exports = mongoose.model('Material', materialSchema, 'materials');
