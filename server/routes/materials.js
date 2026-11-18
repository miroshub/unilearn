// Course material PDFs (/api/courses/:courseId/materials). The instructor uploads; enrolled students download (D19).
const express = require('express');
const { Material } = require('../models');
const { requireSignIn, requireRole } = require('../middleware/auth');
const { allowFields } = require('../middleware/validate');
const { requireOwnCourse } = require('../access');
const { receivePdf } = require('../upload');
const { logInfo } = require('../logger');

// mergeParams: lets this router read :courseId from the address it is mounted on (app.js)
const router = express.Router({ mergeParams: true });

// 🔒 SECURITY 7.2.1 / 7.2.2 — Every route: signed in → instructor or student → the course is their own (OWASP A01, A07)
// For instructors "own" = they teach it; for students = they are enrolled (D19). Admins have no access to material.
router.use(requireSignIn, requireRole('instructor', 'student'), requireOwnCourse);

// Only the fields the page needs (never the file itself)
function toPublicMaterial(material) {
  return { id: material.id, title: material.title, uploadedAt: material.uploadedAt };
}

// GET: the course's material, newest first (the "file" field isn't loaded, see models/Material.js)
router.get('/', async (req, res) => {
  const materials = await Material.find({ courseId: req.course._id }).sort({ uploadedAt: -1 });
  res.json(materials.map(toPublicMaterial));
});

// POST: upload a PDF (a form with "title" and "file").
// 🔒 SECURITY 7.2.2 — Only the course's own instructor; the role and course checks run BEFORE the file is read (OWASP A01)
router.post('/', requireRole('instructor'), receivePdf, allowFields('title'), async (req, res) => {
  const material = await Material.create({
    courseId: req.course._id,
    title: req.body.title,
    file: req.file.buffer,
    uploadedBy: req.user._id,
  });
  logInfo('Material uploaded', { actorId: req.user.id, courseId: req.course.id, materialId: material.id, bytes: req.file.size });
  res.status(201).json(toPublicMaterial(material));
});

// GET /:materialId/file: download one PDF.
router.get('/:materialId/file', async (req, res) => {
  // 🔒 SECURITY 7.2.2 — The material must belong to the course that was checked above (OWASP A01)
  // Without "courseId" here, a student could put their own course in the address and another course's material ID after it.
  const material = await Material.findOne({ _id: req.params.materialId, courseId: req.course._id }).select('+file');
  if (!material) {
    return res.status(404).json({ error: 'Not found' });
  }
  // 🔒 SECURITY 7.2.6 — Sent as a download, never shown inside our page, and never cached by Cloudflare or the browser (OWASP A04)
  res.attachment(`${material.title}.pdf`);
  res.set('Cache-Control', 'private, no-store');
  res.send(material.file);
});

module.exports = router;
