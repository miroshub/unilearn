// Courses: admins create them, assign instructors and enrol students; everyone sees only their own courses.
const express = require('express');
const { Course, Enrollment, User } = require('../models');
const { requireSignIn, requireRole, refuse } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { canSeeCourse } = require('../access');
const { logInfo } = require('../logger');

const router = express.Router();

// All three roles may use the read routes; each one only gets its own courses (see below)
const ALL_ROLES = ['admin', 'instructor', 'student'];

// 🔒 SECURITY 7.2.1 — Every route in this file needs a signed-in, active user (OWASP A07)
router.use(requireSignIn);

// The short view of a course used in lists (instructor names only, no emails)
function toCourseSummary(course) {
  return {
    id: course.id,
    code: course.code,
    title: course.title,
    term: course.term,
    instructors: course.instructorIds.map((instructor) => ({ id: instructor.id, name: instructor.name })),
  };
}

// 🔒 SECURITY 7.2.2 — Ownership built into the search: each role only finds its own courses (OWASP A01)
// Admins: all courses. Instructors: courses they teach. Students: courses they're enrolled in.
async function findOwnCourses(user) {
  if (user.role === 'admin') {
    return Course.find();
  }
  if (user.role === 'instructor') {
    return Course.find({ instructorIds: user._id });
  }
  const enrollments = await Enrollment.find({ studentId: user._id });
  return Course.find({ _id: { $in: enrollments.map((enrollment) => enrollment.courseId) } });
}

// Find the course named in the address (/api/courses/:id), or reply 404
async function findCourse(req, res) {
  const course = await Course.findById(req.params.id);
  if (!course) {
    res.status(404).json({ error: 'Not found' });
  }
  return course;
}

// Find an active user with the given role (used before adding an instructor or a student)
async function findActiveUser(userId, role) {
  const user = await User.findById(userId);
  if (!user || user.role !== role || user.status !== 'active') {
    return null;
  }
  return user;
}

// Reply with one course: instructors for everyone, the student list only for admins and instructors
async function sendCourseDetail(req, res, course) {
  await course.populate('instructorIds', 'name');
  const detail = toCourseSummary(course);

  // 🔒 SECURITY 7.3.5 — Students don't get the class list (other students' names and emails) (OWASP A02)
  if (req.user.role !== 'student') {
    const enrollments = await Enrollment.find({ courseId: course._id })
      .populate('studentId', 'name email studentNumber status');
    detail.students = enrollments
      .filter((enrollment) => enrollment.studentId)
      .map((enrollment) => ({
        id: enrollment.studentId.id,
        name: enrollment.studentId.name,
        email: enrollment.studentId.email,
        studentNumber: enrollment.studentId.studentNumber,
        status: enrollment.studentId.status,
        enrolledAt: enrollment.enrolledAt,
      }));
  }
  res.json(detail);
}

// GET /api/courses: the signed-in user's own courses
router.get('/', requireRole(...ALL_ROLES), async (req, res) => {
  const courses = await findOwnCourses(req.user);
  // Fill in the instructors' names, then sort by term (newest first) and code
  await Course.populate(courses, { path: 'instructorIds', select: 'name' });
  courses.sort((a, b) => b.term.localeCompare(a.term) || a.code.localeCompare(b.code));
  res.json(courses.map(toCourseSummary));
});

// GET /api/courses/:id: one course, if it is one of the user's own
router.get('/:id', requireRole(...ALL_ROLES), async (req, res) => {
  const course = await findCourse(req, res);
  if (!course) {
    return;
  }
  // 🔒 SECURITY 7.2.2 — Ownership check: a student or instructor can't open someone else's course (OWASP A01)
  if (!(await canSeeCourse(req.user, course))) {
    return refuse(req, res, 403, 'NOT_YOUR_COURSE', 'You are not allowed to see this course.');
  }
  await sendCourseDetail(req, res, course);
});

// 🔒 SECURITY 7.2.2 — Everything below changes courses: admins only (OWASP A01, proposal §4)

// POST /api/courses: create a course (Mongoose checks lengths; a duplicate code gets 409)
router.post('/', requireRole('admin'), allowFields('code', 'title', 'term'), async (req, res) => {
  const { code, title, term } = req.body;
  const course = await Course.create({ code, title, term });
  logInfo('Course created', { actorId: req.user.id, courseId: course.id });
  res.status(201);
  await sendCourseDetail(req, res, course);
});

// POST /api/courses/:id/instructors: assign an instructor to the course
router.post('/:id/instructors', requireRole('admin'), allowFields('instructorId'), async (req, res) => {
  const course = await findCourse(req, res);
  if (!course) {
    return;
  }
  // Only a real, active instructor can be assigned (not a student or a made-up ID)
  const instructor = await findActiveUser(req.body.instructorId, 'instructor');
  if (!instructor) {
    return res.status(400).json({ error: 'Choose an active instructor.' });
  }
  // addToSet adds the ID only if it isn't in the list yet
  course.instructorIds.addToSet(instructor._id);
  await course.save();
  logInfo('Instructor assigned', { actorId: req.user.id, courseId: course.id, instructorId: instructor.id });
  await sendCourseDetail(req, res, course);
});

// DELETE /api/courses/:id/instructors/:userId: take an instructor off the course
router.delete('/:id/instructors/:userId', requireRole('admin'), async (req, res) => {
  const course = await findCourse(req, res);
  if (!course) {
    return;
  }
  course.instructorIds.pull(req.params.userId);
  await course.save();
  logInfo('Instructor removed', { actorId: req.user.id, courseId: course.id, instructorId: req.params.userId });
  await sendCourseDetail(req, res, course);
});

// POST /api/courses/:id/enrollments: enrol a student (students can't enrol themselves, D5)
router.post('/:id/enrollments', requireRole('admin'), allowFields('studentId'), async (req, res) => {
  const course = await findCourse(req, res);
  if (!course) {
    return;
  }
  const student = await findActiveUser(req.body.studentId, 'student');
  if (!student) {
    return res.status(400).json({ error: 'Choose an active student.' });
  }
  // The unique index on studentId + courseId refuses a second enrolment (409)
  await Enrollment.create({ studentId: student._id, courseId: course._id });
  logInfo('Student enrolled', { actorId: req.user.id, courseId: course.id, studentId: student.id });
  res.status(201);
  await sendCourseDetail(req, res, course);
});

// DELETE /api/courses/:id/enrollments/:studentId: take a student off the course
router.delete('/:id/enrollments/:studentId', requireRole('admin'), async (req, res) => {
  const course = await findCourse(req, res);
  if (!course) {
    return;
  }
  const result = await Enrollment.deleteOne({ courseId: course._id, studentId: req.params.studentId });
  if (result.deletedCount === 0) {
    return res.status(404).json({ error: 'Not found' });
  }
  logInfo('Student unenrolled', { actorId: req.user.id, courseId: course.id, studentId: req.params.studentId });
  await sendCourseDetail(req, res, course);
});

module.exports = router;
