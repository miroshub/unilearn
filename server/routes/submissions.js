// Student work for one assignment (/api/courses/:courseId/assignments/:assignmentId/submissions). Rules: DECISIONS D21.
const express = require('express');
const { Submission, Grade } = require('../models');
const { requireSignIn, requireRole, refuse } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { requireOwnCourse, requireCourseAssignment } = require('../access');
const { receivePdf } = require('../upload');
const { storePdf, readPdf } = require('../fileCrypto');
const { logInfo } = require('../logger');

// mergeParams: lets this router read :courseId and :assignmentId from the address it is mounted on (app.js)
const router = express.Router({ mergeParams: true });

// 🔒 SECURITY 7.2.1 / 7.2.2 — Every route: signed in → instructor or student → own course → assignment of that course (OWASP A01, A07)
// Admins have no access to student work (proposal §4: they only view grades).
router.use(requireSignIn, requireRole('instructor', 'student'), requireOwnCourse, requireCourseAssignment);

// The submission rules from D21, checked BEFORE the file is read
async function checkCanSubmit(req, res, next) {
  // Exams have no upload: the instructor enters the score (D20)
  if (req.assignment.type === 'exam') {
    return res.status(400).json({ error: 'Exams have no upload. Your instructor enters the score.' });
  }
  // 🔒 SECURITY 7.2.2 — Deadline checked with the SERVER's clock, never a time sent by the browser (OWASP A01, D21)
  if (Date.now() > req.assignment.dueAt.getTime()) {
    return refuse(req, res, 403, 'DEADLINE_PASSED', 'The deadline has passed.');
  }
  // 🔒 SECURITY 7.2.2 — A graded submission is locked: it can't be swapped after the mark is given (OWASP A01, D21)
  if (await Grade.exists({ studentId: req.user._id, assignmentId: req.assignment._id })) {
    return refuse(req, res, 409, 'LOCKED', 'This work has been graded and is locked.');
  }
  next();
}

// (The instructor's list of submissions is part of the grade book: routes/grades.js)

// PUT /mine: a student uploads their PDF, or replaces it before the deadline (one per student, D21).
// Order: role → deadline / lock rules → only then read the file (size + PDF check) → no other form fields.
router.put('/mine', requireRole('student'), checkCanSubmit, receivePdf, allowFields(), async (req, res) => {
  // The student ID comes from the signed-in user, never from the request
  let submission = await Submission.findOne({ assignmentId: req.assignment._id, studentId: req.user._id });
  const isFirstUpload = !submission;
  if (isFirstUpload) {
    submission = new Submission({ assignmentId: req.assignment._id, studentId: req.user._id });
  } else {
    // Before the deadline a new upload replaces the old PDF and updates the time (D21)
    submission.submittedAt = new Date();
  }
  // Encrypt the PDF and save its SHA-256 fingerprint (D38, fileCrypto.js)
  storePdf(submission, req.file.buffer);
  await submission.save();
  logInfo(isFirstUpload ? 'Work submitted' : 'Work resubmitted',
    { actorId: req.user.id, assignmentId: req.assignment.id, submissionId: submission.id, bytes: req.file.size });
  // The fingerprint is the student's receipt: the page compares it with the file they chose
  res.status(isFirstUpload ? 201 : 200).json({ id: submission.id, submittedAt: submission.submittedAt, fileSha256: submission.fileSha256 });
});

// GET /:submissionId/file: download one submitted PDF
router.get('/:submissionId/file', async (req, res) => {
  const submission = await Submission.findOne({ _id: req.params.submissionId, assignmentId: req.assignment._id }).select('+file');
  if (!submission) {
    return res.status(404).json({ error: 'Not found' });
  }
  // 🔒 SECURITY 7.2.2 — Ownership: a student may only download THEIR OWN work; the course's instructor may download all (OWASP A01)
  if (req.user.role === 'student' && !submission.studentId.equals(req.user._id)) {
    return refuse(req, res, 403, 'NOT_YOUR_SUBMISSION', 'You can only download your own work.');
  }
  // Decrypt first, and refuse if the stored file was changed since upload (fileCrypto.js).
  // This comes before the download headers, so a refusal is sent as a normal error, not as a "PDF".
  const pdf = readPdf(submission);
  // 🔒 SECURITY 7.2.6 — Sent as a download, never shown inside our page, never cached (OWASP A04)
  res.attachment(`${req.assignment.title}.pdf`);
  res.set('Cache-Control', 'private, no-store');
  res.send(pdf);
});

module.exports = router;
