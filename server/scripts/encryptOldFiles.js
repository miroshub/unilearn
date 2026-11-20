// One-off: protects the PDFs uploaded before encryption and signatures existed (Phases 6–7, DECISIONS D38, D40).
// For every submission and material without a fingerprint: fingerprint it, encrypt it with a new session key,
// and (for submissions) sign its receipt. Safe to run twice: records that already have a fingerprint are skipped.
// Usage: npm run encrypt-old-files --prefix server
const mongoose = require('mongoose');
const { connectToDatabase } = require('../db');
const { Submission, Material } = require('../models');
const { getMasterKey, storePdf } = require('../fileCrypto');
const { loadSigningIdentity, signText, receiptText } = require('../pki');

// Protect every not-yet-encrypted record of one model (Submission or Material); returns how many
async function protectAll(Model) {
  const oldRecords = await Model.find({ fileSha256: { $exists: false } }).select('+file');
  for (const record of oldRecords) {
    // record.file is still the plain PDF here
    storePdf(record, record.file);
    if (Model === Submission) {
      record.receiptSignature = signText(receiptText(record));
    }
    await record.save();
  }
  return oldRecords.length;
}

// Check the key and certificates, connect, protect both collections, report
async function encryptOldFiles() {
  getMasterKey();
  loadSigningIdentity();
  await connectToDatabase();
  const submissions = await protectAll(Submission);
  const materials = await protectAll(Material);
  console.log(`Encrypted ${submissions} submission(s) and ${materials} material file(s).`);
  await mongoose.disconnect();
}

encryptOldFiles().catch((err) => {
  console.error('Could not encrypt old files:', err.message);
  process.exit(1);
});
