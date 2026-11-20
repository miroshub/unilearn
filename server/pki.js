// UniLearn's certificates and digital signatures (DECISIONS D40).
// The server signs submission receipts and grades with its private RSA key. Anyone can check
// a signature with the public key in the signing certificate, which the UniLearn Root CA issued.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { logWarning } = require('./logger');

// RSA-PSS with SHA-256: the modern RSA signature scheme (random padding). Salt 32 bytes = SHA-256 length.
const SIGN_OPTIONS = { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };

// Filled in once by loadSigningIdentity() at startup
let identity = null;

// 🔒 SECURITY 7.3.9 — Certificate check at startup, as in Lecture 8 "How to verify a certificate" (OWASP A02)
// 1) the root CA is a real CA and signed itself, 2) the signing certificate was issued AND signed by
// our root CA, 3) neither certificate is expired or not yet valid, 4) the private key in the settings
// belongs to the signing certificate. Any failure stops the server (fail closed).
function loadSigningIdentity() {
  // Where the two PUBLIC certificates live (made once by scripts/make-pki.sh). PKI_FOLDER is only for tests.
  const pkiFolder = process.env.PKI_FOLDER || path.join(__dirname, 'pki');
  if (!fs.existsSync(path.join(pkiFolder, 'unilearn-signing.crt'))) {
    throw new Error('No UniLearn certificates found in server/pki. Make them with server/scripts/make-pki.sh (SETUP_GUIDE 6.10).');
  }
  const rootCa = new crypto.X509Certificate(fs.readFileSync(path.join(pkiFolder, 'unilearn-root-ca.crt')));
  const signingCert = new crypto.X509Certificate(fs.readFileSync(path.join(pkiFolder, 'unilearn-signing.crt')));
  const privateKey = crypto.createPrivateKey(Buffer.from(process.env.SIGNING_PRIVATE_KEY || '', 'base64'));

  if (!rootCa.ca || !rootCa.verify(rootCa.publicKey)) {
    throw new Error('Certificate check failed: the root certificate is not a valid self-signed CA.');
  }
  if (signingCert.ca || !signingCert.checkIssued(rootCa) || !signingCert.verify(rootCa.publicKey)) {
    throw new Error('Certificate check failed: the signing certificate was not issued and signed by the UniLearn Root CA.');
  }
  const now = new Date();
  for (const cert of [rootCa, signingCert]) {
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      throw new Error(`Certificate check failed: "${cert.subject}" is expired or not valid yet (${cert.validFrom} – ${cert.validTo}).`);
    }
  }
  if (!signingCert.checkPrivateKey(privateKey)) {
    throw new Error('Certificate check failed: SIGNING_PRIVATE_KEY does not belong to the signing certificate.');
  }

  identity = { rootCa, signingCert, privateKey };
  return identity;
}

// The loaded identity (loads it on first use, e.g. in scripts)
function getIdentity() {
  return identity || loadSigningIdentity();
}

// 🔒 SECURITY 7.3.8 — Digital signature: hash the text with SHA-256, sign the hash with our PRIVATE key (OWASP A08)
// Only the UniLearn server has the private key, so only it can make a valid signature (authenticity),
// and changing even one character of the text breaks the signature (integrity).
function signText(text) {
  return crypto.sign('sha256', Buffer.from(text), { key: getIdentity().privateKey, ...SIGN_OPTIONS }).toString('base64');
}

// 🔒 SECURITY 7.3.8 — Check a signature with the PUBLIC key from the signing certificate (OWASP A08)
// Returns false (never throws) for a missing, broken or wrong signature.
function verifyText(text, signatureBase64) {
  if (!signatureBase64) {
    return false;
  }
  try {
    const publicKey = getIdentity().signingCert.publicKey;
    return crypto.verify('sha256', Buffer.from(text), { key: publicKey, ...SIGN_OPTIONS }, Buffer.from(signatureBase64, 'base64'));
  } catch {
    return false;
  }
}

// The exact text that is signed for a submission receipt (one fact per line, easy to read)
function receiptText(submission) {
  return [
    'UniLearn submission receipt',
    `submission: ${submission.id}`,
    `assignment: ${submission.assignmentId}`,
    `student: ${submission.studentId}`,
    `file SHA-256: ${submission.fileSha256}`,
    `submitted at: ${submission.submittedAt.toISOString()}`,
  ].join('\n');
}

// The exact text that is signed for a grade
function gradeText(grade) {
  return [
    'UniLearn grade',
    `grade: ${grade.id}`,
    `assignment: ${grade.assignmentId}`,
    `student: ${grade.studentId}`,
    `score: ${grade.score}`,
    `graded by: ${grade.gradedBy}`,
    `graded at: ${grade.gradedAt.toISOString()}`,
  ].join('\n');
}

// 🔒 SECURITY 7.3.8 — Every time a grade is shown, its signature is checked again (OWASP A08, A09)
// A score changed directly in the database (not through UniLearn) no longer matches its signature:
// the page shows a warning, and the Render log gets a WARN line for us to investigate.
function isGradeSignatureValid(grade) {
  const valid = verifyText(gradeText(grade), grade.signature);
  if (!valid) {
    logWarning('Grade signature check failed', { gradeId: grade.id });
  }
  return valid;
}

// A student's signed receipt as sent to the browser: the text, the signature, and the server's own check of it.
// null for a file uploaded before signatures existed (until scripts/encryptOldFiles.js has signed it).
function receiptFor(submission) {
  if (!submission.receiptSignature) {
    return null;
  }
  const text = receiptText(submission);
  return { text, signature: submission.receiptSignature, signatureValid: verifyText(text, submission.receiptSignature) };
}

// The public facts the browser needs to check a signature itself: certificates and the public key
function publicCertificateInfo() {
  const { rootCa, signingCert } = getIdentity();
  return {
    signingCertificate: {
      subject: signingCert.subject,
      issuer: signingCert.issuer,
      serialNumber: signingCert.serialNumber,
      validFrom: signingCert.validFrom,
      validTo: signingCert.validTo,
      fingerprintSha256: signingCert.fingerprint256,
      pem: signingCert.toString(),
    },
    rootCertificate: {
      subject: rootCa.subject,
      validTo: rootCa.validTo,
      fingerprintSha256: rootCa.fingerprint256,
      pem: rootCa.toString(),
    },
    // The public key in "SPKI" form, which the browser's Web Crypto can import
    publicKeySpki: signingCert.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    algorithm: 'RSA-PSS with SHA-256, salt length 32',
  };
}

module.exports = {
  loadSigningIdentity, signText, verifyText, receiptText, gradeText, isGradeSignatureValid, receiptFor, publicCertificateInfo,
};
