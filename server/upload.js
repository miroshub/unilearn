// Shared PDF upload helper: used for course material (Phase 6) and student submissions (Phase 7).
const multer = require('multer');
const { rejectOperatorKeys } = require('./middleware/security');
const { logWarning } = require('./logger');

const MAX_PDF_BYTES = 10 * 1024 * 1024;

// 🔒 SECURITY 7.2.6 — Uploads: one file, max 10 MB, kept in memory (never written to disk) (OWASP A04)
// Multer stops reading as soon as the file passes 10 MB, so a huge upload can't fill the server's memory.
// The few text fields (like "title") are limited too.
const readUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_PDF_BYTES, files: 1, fields: 5, fieldSize: 1000 },
}).single('file');

// True if the bytes start with "%PDF-", the signature every real PDF file begins with
function looksLikePdf(buffer) {
  return buffer.length > 5 && buffer.subarray(0, 5).toString('latin1') === '%PDF-';
}

// 🔒 SECURITY 7.2.6 — Only real PDFs are accepted, checked by the file's first bytes (OWASP A04)
// The file name and the type the browser claims can be faked (virus.exe renamed to notes.pdf),
// so we look at the content itself.
function requirePdf(req, res, next) {
  if (!req.file) {
    return res.status(400).json({ error: 'Choose a PDF file.' });
  }
  if (!looksLikePdf(req.file.buffer)) {
    logWarning('Upload refused: not a PDF', { ip: req.ip, path: req.baseUrl + req.path, userId: req.user.id });
    return res.status(400).json({ error: 'Only PDF files are allowed.' });
  }
  next();
}

// Use in a route AFTER the sign-in, role and ownership checks, so strangers can't make us read 10 MB.
// The text fields are checked for "$" keys again, because they only exist once multer has read them.
const receivePdf = [readUpload, rejectOperatorKeys, requirePdf];

module.exports = { receivePdf, MAX_PDF_BYTES };
