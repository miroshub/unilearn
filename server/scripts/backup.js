// Weekly backup (SECURITY 7.3.6): copies every UniLearn collection into an ENCRYPTED folder on this PC.
// Usage: npm run backup --prefix server
// Output: <BACKUP_FOLDER or ~/unilearn-backups>/<date-time>/ with one .enc file per collection and a manifest.json.
// Restore with scripts/restoreBackup.js (SETUP_GUIDE Part 9).
const fs = require('fs');
const os = require('os');
const path = require('path');
const mongoose = require('mongoose');
const { connectToDatabase } = require('../db');
const models = require('../models');
const { fingerprint, getMasterKey, encryptFile } = require('../fileCrypto');

// EJSON ("extended JSON") keeps MongoDB types like ObjectId, Date and Buffer, so a restore gives back exactly the same data
const { EJSON } = mongoose.mongo.BSON;

// Folder for this backup, named after the date and time, e.g. 2026-11-20T15-30-00
function makeBackupFolder() {
  const parent = process.env.BACKUP_FOLDER || path.join(os.homedir(), 'unilearn-backups');
  const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
  const folder = path.join(parent, stamp);
  fs.mkdirSync(folder, { recursive: true });
  return folder;
}

// 🔒 SECURITY 7.3.6 — Backup of every collection, encrypted with AES-256-GCM before it is written to disk (OWASP A02)
// A backup holds names, emails and grades. Each collection gets its own session key (same envelope
// encryption as the PDFs, fileCrypto.js), so a copied or stolen backup folder is useless without the master key.
// The manifest keeps a SHA-256 of each collection, so the restore can prove nothing was changed.
async function backup() {
  getMasterKey();
  await connectToDatabase();
  const folder = makeBackupFolder();
  const manifest = { createdAt: new Date(), database: mongoose.connection.name, collections: {} };

  for (const Model of Object.values(models)) {
    const name = Model.collection.collectionName;
    // Read the raw documents (including the encrypted PDF bytes that lists normally leave out)
    const documents = await mongoose.connection.db.collection(name).find().toArray();
    const plain = Buffer.from(EJSON.stringify(documents, { relaxed: false }));
    const { file, wrappedKey } = encryptFile(plain, name);
    fs.writeFileSync(path.join(folder, `${name}.enc`), file);
    manifest.collections[name] = {
      documents: documents.length,
      sha256: fingerprint(plain),
      wrappedKey: wrappedKey.toString('base64'),
    };
    console.log(`${name}: ${documents.length} document(s)`);
  }

  fs.writeFileSync(path.join(folder, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log(`Backup saved in ${folder}`);
  await mongoose.disconnect();
}

backup().catch((err) => {
  console.error('Backup failed:', err.message);
  process.exit(1);
});
