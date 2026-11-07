// An assignment (students upload a PDF) or an exam (the instructor enters scores) — DECISIONS D20.
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const assignmentSchema = new mongoose.Schema({
  courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  type: { type: String, required: true, enum: ['assignment', 'exam'], default: 'assignment' },
  // Deadline, always compared with the server's clock (D21)
  dueAt: { type: Date, required: true },
  maxScore: { type: Number, required: true, min: 1, max: 1000 },
}, { strict: 'throw', strictQuery: 'throw' });

module.exports = mongoose.model('Assignment', assignmentSchema, 'assignments');
