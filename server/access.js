// Ownership checks: does this course belong to this user? Shared by every course-related route.
const { Course, Enrollment } = require('./models');
const { refuse } = require('./middleware/auth');

// True if the user is one of the course's instructors
function isCourseInstructor(user, course) {
  return course.instructorIds.some((instructorId) => instructorId.equals(user._id));
}

// True if the user is enrolled in the course as a student
async function isEnrolled(user, course) {
  return Boolean(await Enrollment.exists({ studentId: user._id, courseId: course._id }));
}

// 🔒 SECURITY 7.2.2 — Ownership check: is this course one of the user's own? (OWASP A01)
// Admins: every course. Instructors: only courses they teach. Students: only courses they're enrolled in.
// The role and the links come from our database, never from the browser.
async function canSeeCourse(user, course) {
  if (user.role === 'admin') {
    return true;
  }
  if (user.role === 'instructor') {
    return isCourseInstructor(user, course);
  }
  return isEnrolled(user, course);
}

// 🔒 SECURITY 7.2.2 — Middleware: the course in the address (/courses/:courseId/...) must be the user's own (OWASP A01)
// Runs after requireSignIn and requireRole. Afterwards, req.course is the course.
// With requireRole('instructor') in front, this means "an instructor of THIS course".
async function requireOwnCourse(req, res, next) {
  const course = await Course.findById(req.params.courseId);
  if (!course) {
    return res.status(404).json({ error: 'Not found' });
  }
  if (!(await canSeeCourse(req.user, course))) {
    return refuse(req, res, 403, 'NOT_YOUR_COURSE', 'You are not allowed to use this course.');
  }
  req.course = course;
  next();
}

module.exports = { isCourseInstructor, isEnrolled, canSeeCourse, requireOwnCourse };
