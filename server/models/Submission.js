// A student's PDF for one assignment, stored inside the document as bytes (D7).
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const submissionSchema = new mongoose.Schema({
  assignmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assignment', required: true },
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // The PDF itself. "select: false" means lists never load the file; only a download asks for it.
  file: { type: Buffer, required: true, select: false },
  submittedAt: { type: Date, default: Date.now },
}, { strict: 'throw', strictQuery: 'throw' });

// One submission per student per assignment (D21)
submissionSchema.index({ assignmentId: 1, studentId: 1 }, { unique: true });

module.exports = mongoose.model('Submission', submissionSchema, 'submissions');
