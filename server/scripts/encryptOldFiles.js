// One-off: encrypts the PDFs that were uploaded before file encryption existed (Phases 6–7, DECISIONS D38).
// It finds every submission and material without a fingerprint, then fingerprints and encrypts it.
// Safe to run twice: records that already have a fingerprint are skipped.
// Usage: npm run encrypt-old-files --prefix server
const mongoose = require('mongoose');
const { connectToDatabase } = require('../db');
const { Submission, Material } = require('../models');
const { getKey, storePdf } = require('../fileCrypto');

// Encrypt every not-yet-encrypted record of one model (Submission or Material); returns how many
async function encryptAll(Model) {
  const oldRecords = await Model.find({ fileSha256: { $exists: false } }).select('+file');
  for (const record of oldRecords) {
    // record.file is still the plain PDF here
    storePdf(record, record.file);
    await record.save();
  }
  return oldRecords.length;
}

// Check the key, connect, encrypt both collections, report
async function encryptOldFiles() {
  getKey();
  await connectToDatabase();
  const submissions = await encryptAll(Submission);
  const materials = await encryptAll(Material);
  console.log(`Encrypted ${submissions} submission(s) and ${materials} material file(s).`);
  await mongoose.disconnect();
}

encryptOldFiles().catch((err) => {
  console.error('Could not encrypt old files:', err.message);
  process.exit(1);
});
