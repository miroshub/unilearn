// "Who am I?" — tells the React app the signed-in user's name and role,
// and lets every user download all the personal data UniLearn holds about them (GDPR, D22).
const express = require('express');
const { Course, Enrollment, Submission, Grade } = require('../models');
const { requireSignIn } = require('../middleware/auth');
const { logInfo } = require('../logger');

const router = express.Router();

// GET /api/me: only the fields the page needs (never the whole user document)
router.get('/', requireSignIn, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, role: req.user.role });
});

// 🔒 SECURITY 7.3.5 — GDPR right of access: "Download my data" (OWASP A01, D22)
// GET /api/me/data. Every search uses req.user (from the sign-in check), never an ID from the browser,
// so a user can only ever download their OWN data. PDF bytes are left out (students download those per assignment).
router.get('/data', requireSignIn, async (req, res) => {
  const user = req.user;
  const enrollments = await Enrollment.find({ studentId: user._id }).populate('courseId', 'code title term');
  const coursesTaught = await Course.find({ instructorIds: user._id });
  const submissions = await Submission.find({ studentId: user._id }).populate('assignmentId', 'title');
  const grades = await Grade.find({ studentId: user._id }).populate('assignmentId', 'title maxScore');

  logInfo('Personal data downloaded', { userId: user.id });
  res.json({
    about: 'All personal data UniLearn holds about you. Your PDFs are not inside this file: download them from your courses.',
    downloadedAt: new Date(),
    profile: {
      name: user.name,
      email: user.email,
      role: user.role,
      studentNumber: user.studentNumber,
      status: user.status,
      accountCreatedAt: user.createdAt,
    },
    enrolments: enrollments.map((enrollment) => ({
      course: enrollment.courseId ? `${enrollment.courseId.code} ${enrollment.courseId.title}` : 'Deleted course',
      term: enrollment.courseId?.term,
      enrolledAt: enrollment.enrolledAt,
    })),
    coursesTaught: coursesTaught.map((course) => `${course.code} ${course.title} (${course.term})`),
    submissions: submissions.map((submission) => ({
      assignment: submission.assignmentId?.title,
      submittedAt: submission.submittedAt,
      fileSha256: submission.fileSha256,
    })),
    grades: grades.map((grade) => ({
      assignment: grade.assignmentId?.title,
      score: grade.score,
      maxScore: grade.assignmentId?.maxScore,
      gradedAt: grade.gradedAt,
    })),
  });
});

module.exports = router;
