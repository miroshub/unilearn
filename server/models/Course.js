// A course in one term, with the instructors who teach it.
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const courseSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, trim: true, uppercase: true, maxlength: 20 },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  term: { type: String, required: true, trim: true, maxlength: 20 },
  // Instructors of this course; used for the "own courses only" check (7.2.2)
  instructorIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { strict: 'throw', strictQuery: 'throw' });

module.exports = mongoose.model('Course', courseSchema, 'courses');
