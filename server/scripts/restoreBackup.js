// Restore a backup made by scripts/backup.js into an EMPTY database (SECURITY 7.3.6).
// Usage: npm run restore-backup --prefix server -- "C:\Users\you\unilearn-backups\2026-11-20T15-30-00"
// MONGODB_URI must point at the new, empty database. The script refuses to write over existing data.
// FILE_ENCRYPTION_KEY must be the same master key as when the backup was made.
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { connectToDatabase } = require('../db');
const { decryptFile } = require('../fileCrypto');

const { EJSON } = mongoose.mongo.BSON;

// Decrypt one collection file and prove it is unchanged (decryptFile throws if the SHA-256 differs)
function readCollection(folder, name, info) {
  const file = fs.readFileSync(path.join(folder, `${name}.enc`));
  const plain = decryptFile(file, Buffer.from(info.wrappedKey, 'base64'), name, info.sha256);
  return EJSON.parse(plain.toString(), { relaxed: false });
}

// Check the whole backup first, then refuse if the database already has data, then copy everything in
async function restoreBackup(folder) {
  if (!folder || !fs.existsSync(path.join(folder, 'manifest.json'))) {
    throw new Error('Give the backup folder (the one with manifest.json) after "--".');
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(folder, 'manifest.json'), 'utf8'));

  // 1) Decrypt and check every collection BEFORE touching the database
  const collections = {};
  for (const [name, info] of Object.entries(manifest.collections)) {
    collections[name] = readCollection(folder, name, info);
    if (collections[name].length !== info.documents) {
      throw new Error(`${name}: expected ${info.documents} document(s), found ${collections[name].length}.`);
    }
  }
  console.log(`Backup from ${manifest.createdAt} decrypted and checked.`);

  // 2) Never write over live data
  await connectToDatabase();
  const database = mongoose.connection.db;
  for (const name of Object.keys(collections)) {
    if (await database.collection(name).countDocuments() > 0) {
      throw new Error(`The database is not empty ("${name}" has data). Restore only into a new, empty database.`);
    }
  }

  // 3) Copy the documents in, keeping their IDs, so every link between them still works
  for (const [name, documents] of Object.entries(collections)) {
    if (documents.length > 0) {
      await database.collection(name).insertMany(documents);
    }
    console.log(`${name}: ${documents.length} document(s) restored`);
  }
  // Rebuild the indexes from the models (unique email, one grade per student and assignment, ...)
  await mongoose.connection.syncIndexes();
  await mongoose.disconnect();
  console.log('Restore finished.');
}

restoreBackup(process.argv[2]).catch(async (err) => {
  console.error('Restore failed:', err.message);
  await mongoose.disconnect();
  process.exit(1);
});
