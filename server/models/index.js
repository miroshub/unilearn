// All UniLearn models in one place: the 7 collections from proposal §5, plus materials (D19).
const User = require('./User');
const Course = require('./Course');
const Enrollment = require('./Enrollment');
const Assignment = require('./Assignment');
const Submission = require('./Submission');
const Grade = require('./Grade');
const AuditLog = require('./AuditLog');
const Material = require('./Material');

module.exports = { User, Course, Enrollment, Assignment, Submission, Grade, AuditLog, Material };
