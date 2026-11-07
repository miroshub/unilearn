// A student's score for one assignment or exam. Every change is audit-logged (7.6.1).
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const gradeSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assignmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assignment', required: true },
  // Checked against the assignment's maxScore when grading (Phase 8)
  score: { type: Number, required: true, min: 0 },
  // The instructor who gave the grade
  gradedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { strict: 'throw', strictQuery: 'throw' });

// One grade per student per assignment
gradeSchema.index({ studentId: 1, assignmentId: 1 }, { unique: true });

module.exports = mongoose.model('Grade', gradeSchema, 'grades');
