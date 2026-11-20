// Grades for one assignment or exam (/api/courses/:courseId/assignments/:assignmentId/grades). Phase 8, DECISIONS D39.
// Instructors grade their own courses; admins only read (separation of duties); students see their own
// score in the assignments list (routes/assignments.js), not here.
const express = require('express');
const { Enrollment, Submission, Grade } = require('../models');
const { requireSignIn, requireRole } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { requireOwnCourse, requireCourseAssignment } = require('../access');
const { writeAuditLog } = require('../audit');
const { signText, gradeText, isGradeSignatureValid } = require('../pki');
const { logInfo } = require('../logger');

// mergeParams: lets this router read :courseId and :assignmentId from the address it is mounted on (app.js)
const router = express.Router({ mergeParams: true });

// 🔒 SECURITY 7.2.1 / 7.2.2 — Every route: signed in → admin or instructor → own course → assignment of that course (OWASP A01, A07)
// For an instructor "own course" means they teach it; admins may open every course (read only, see PUT below).
router.use(requireSignIn, requireRole('admin', 'instructor'), requireOwnCourse, requireCourseAssignment);

// One row of the grade book: a student, their submission (if any) and their score (if any)
function toGradeRow(student, submission, grade, isInstructor) {
  const row = {
    studentId: student.id,
    studentName: student.name,
    studentNumber: student.studentNumber,
    submittedAt: submission ? submission.submittedAt : null,
    score: grade ? grade.score : null,
    gradedAt: grade ? grade.gradedAt : null,
    // false = the score no longer matches UniLearn's signature (changed outside UniLearn)
    signatureValid: grade ? isGradeSignatureValid(grade) : null,
  };
  // 🔒 SECURITY 7.2.2 — Only the course's instructor gets the link to the student's work and its fingerprint (OWASP A01)
  // Admins see scores only: §4 gives them grades, not student work (D37).
  if (isInstructor && submission) {
    row.submissionId = submission.id;
    row.fileSha256 = submission.fileSha256;
  }
  return row;
}

// GET /: the grade book — every enrolled student with their submission and score
router.get('/', async (req, res) => {
  const enrollments = await Enrollment.find({ courseId: req.course._id }).populate('studentId', 'name studentNumber');
  const submissions = await Submission.find({ assignmentId: req.assignment._id });
  const grades = await Grade.find({ assignmentId: req.assignment._id });
  const isInstructor = req.user.role === 'instructor';

  const rows = enrollments
    .filter((enrollment) => enrollment.studentId)
    .map((enrollment) => {
      const student = enrollment.studentId;
      const submission = submissions.find((item) => item.studentId.equals(student._id));
      const grade = grades.find((item) => item.studentId.equals(student._id));
      return toGradeRow(student, submission, grade, isInstructor);
    });
  rows.sort((a, b) => a.studentName.localeCompare(b.studentName));
  res.json(rows);
});

// PUT /:studentId — give or change one student's score. Body: { "score": 42 }
// 🔒 SECURITY 7.2.2 — Instructors only: an admin gets 403 here, so admins can never change a grade (OWASP A01, separation of duties)
router.put('/:studentId', requireRole('instructor'), allowFields('score'), async (req, res) => {
  const { score } = req.body;
  const maxScore = req.assignment.maxScore;
  // 🔒 SECURITY 7.2.3 — The score must be a real number from 0 to this assignment's maximum (OWASP A03)
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > maxScore) {
    return res.status(400).json({ error: `The score must be a number from 0 to ${maxScore}.` });
  }

  // 🔒 SECURITY 7.2.2 — The student must be enrolled in THIS course (OWASP A01)
  const enrollment = await Enrollment.findOne({ courseId: req.course._id, studentId: req.params.studentId })
    .populate('studentId', 'name');
  if (!enrollment || !enrollment.studentId) {
    return res.status(404).json({ error: 'Not found' });
  }
  const student = enrollment.studentId;

  // An assignment is graded on the PDF the student handed in; exams have no upload (D20)
  if (req.assignment.type === 'assignment'
    && !(await Submission.exists({ assignmentId: req.assignment._id, studentId: student._id }))) {
    return res.status(400).json({ error: 'This student has not submitted anything to grade yet.' });
  }

  let grade = await Grade.findOne({ assignmentId: req.assignment._id, studentId: student._id });
  const oldScore = grade ? grade.score : null;
  if (oldScore === score) {
    return res.json({ studentId: student.id, score, gradedAt: grade.gradedAt });
  }
  if (!grade) {
    grade = new Grade({ assignmentId: req.assignment._id, studentId: student._id });
  }
  grade.score = score;
  grade.gradedBy = req.user._id;
  grade.gradedAt = new Date();
  // 🔒 SECURITY 7.3.8 — UniLearn signs the grade (student, assignment, score, who, when) with its private key (OWASP A08)
  grade.signature = signText(gradeText(grade));
  // The unique index (student + assignment) turns two grades for the same work into a 409
  await grade.save();

  // 🔒 SECURITY 7.6.1 — Every grade given or changed is audit-logged with the old and new score (OWASP A09)
  // Nobody can quietly change a mark: the audit log has no edit or delete route.
  const target = `grades/${grade.id} (${student.name}, ${req.assignment.title})`.slice(0, 200);
  await writeAuditLog(req.user, oldScore === null ? 'grade.create' : 'grade.change', target, { score: oldScore }, { score });
  logInfo('Grade saved', { actorId: req.user.id, gradeId: grade.id, assignmentId: req.assignment.id });

  res.status(oldScore === null ? 201 : 200).json({ studentId: student.id, score, gradedAt: grade.gradedAt });
});

module.exports = router;
