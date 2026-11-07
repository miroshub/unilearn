// One document per person. Passwords are NOT here: Clerk holds them (proposal §5).
const mongoose = require('mongoose');

// 🔒 SECURITY 7.2.3 / 7.3.4 — Unknown fields are an error, not stored or ignored (OWASP A03)
const userSchema = new mongoose.Schema({
  // The user's ID in Clerk, used to match a signed-in person to this document
  clerkId: { type: String, required: true, unique: true, trim: true, maxlength: 100 },
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true, maxlength: 254 },
  // 🔒 SECURITY 7.2.2 — Only these three roles can exist (OWASP A01)
  role: { type: String, required: true, enum: ['admin', 'instructor', 'student'] },
  // Students only; staff leave it empty
  studentNumber: { type: String, trim: true, maxlength: 20 },
  // 🔒 SECURITY 7.5.5 — Disabled accounts are refused by the server (OWASP A01)
  status: { type: String, required: true, enum: ['active', 'disabled'], default: 'active' },
  createdAt: { type: Date, default: Date.now },
}, { strict: 'throw', strictQuery: 'throw' });

module.exports = mongoose.model('User', userSchema, 'users');
