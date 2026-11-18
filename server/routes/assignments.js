// Assignments and exams of one course (/api/courses/:courseId/assignments). Instructors add them to their own courses.
const express = require('express');
const { Assignment } = require('../models');
const { requireSignIn, requireRole } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { requireOwnCourse } = require('../access');
const { logInfo } = require('../logger');

// mergeParams: lets this router read :courseId from the address it is mounted on (app.js)
const router = express.Router({ mergeParams: true });

// Only the fields the pages need
function toPublicAssignment(assignment) {
  return {
    id: assignment.id,
    title: assignment.title,
    type: assignment.type,
    dueAt: assignment.dueAt,
    maxScore: assignment.maxScore,
  };
}

// GET: the course's assignments and exams, by deadline.
// 🔒 SECURITY 7.2.1 / 7.2.2 — Signed in → any role → only if the course is the user's own (OWASP A01, A07)
// Admins may read them too (they need them for the read-only grade view, Phase 8).
router.get('/', requireSignIn, requireRole('admin', 'instructor', 'student'), requireOwnCourse, async (req, res) => {
  const assignments = await Assignment.find({ courseId: req.course._id }).sort({ dueAt: 1 });
  res.json(assignments.map(toPublicAssignment));
});

// POST: add an assignment or exam to the course.
// 🔒 SECURITY 7.2.2 — Signed in → instructor → instructor of THIS course (OWASP A01, proposal §4)
// Admins can't add assignments: in §4 that is the instructor's job only.
router.post('/', requireSignIn, requireRole('instructor'), requireOwnCourse,
  allowFields('title', 'type', 'dueAt', 'maxScore'), async (req, res) => {
    const { title, type, dueAt, maxScore } = req.body;
    // courseId comes from the checked course, never from the request body.
    // Mongoose checks the rest: title length, type is "assignment" or "exam", a real date, maxScore 1–1000.
    const assignment = await Assignment.create({ courseId: req.course._id, title, type, dueAt, maxScore });
    logInfo('Assignment created', { actorId: req.user.id, courseId: req.course.id, assignmentId: assignment.id });
    res.status(201).json(toPublicAssignment(assignment));
  });

module.exports = router;
