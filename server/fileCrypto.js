// Cryptography for stored PDFs (DECISIONS D38): a SHA-256 fingerprint, and AES-256-GCM encryption.
// Uses Node's built-in "crypto" module, so no extra package is needed.
const crypto = require('crypto');

// AES-GCM uses a 12-byte random "IV" (number used once) and produces a 16-byte authentication tag
const IV_BYTES = 12;
const TAG_BYTES = 16;

// 🔒 SECURITY 7.2.9 — SHA-256 fingerprint of a file: any change to the file gives a different fingerprint (OWASP A08)
// Returned as 64 hex characters. Students can compare it with their own copy
// (Windows: Get-FileHash file.pdf), so they can prove which exact file they handed in.
function fingerprint(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Read the 256-bit key from the settings (64 hex characters = 32 bytes), or stop with a clear message
function getKey() {
  const hex = process.env.FILE_ENCRYPTION_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('FILE_ENCRYPTION_KEY must be 64 hex characters. Make one as shown in SETUP_GUIDE 6.9.');
  }
  return Buffer.from(hex, 'hex');
}

// 🔒 SECURITY 7.3.7 — PDFs are encrypted by our app with AES-256-GCM before they reach the database (OWASP A02)
// Atlas already encrypts its disks, but anyone who can read the database (a stolen DB password,
// a leaked backup, a database admin) would still see the PDFs. With this layer they only see
// random bytes: the key lives in Render's settings, never next to the data.
// "recordId" (the submission or material ID) is mixed into the tag, so encrypted bytes copied
// into another record fail to decrypt.
// Stored layout: [12-byte IV][16-byte tag][encrypted PDF]
function encryptFile(plainBuffer, recordId) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  cipher.setAAD(Buffer.from(String(recordId)));
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

// 🔒 SECURITY 7.3.7 / 7.2.9 — Decrypt a stored PDF and prove it is unchanged before anyone gets it (OWASP A02, A08)
// Two checks: (1) GCM's tag fails if even one stored byte was changed or the key is wrong;
// (2) the decrypted file must still have the fingerprint saved at upload time.
// Either failure throws, so the error handler logs it and the user gets a generic 500.
function decryptFile(storedBuffer, recordId, expectedSha256) {
  const iv = storedBuffer.subarray(0, IV_BYTES);
  const tag = storedBuffer.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const encrypted = storedBuffer.subarray(IV_BYTES + TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
  decipher.setAAD(Buffer.from(String(recordId)));
  decipher.setAuthTag(tag);
  // final() throws "Unsupported state or unable to authenticate data" if the tag doesn't match
  const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  if (fingerprint(plain) !== expectedSha256) {
    throw new Error(`File integrity check failed for record ${recordId}`);
  }
  return plain;
}

// Put a freshly uploaded PDF into a submission or material record: encrypted file + fingerprint
function storePdf(record, plainBuffer) {
  record.fileSha256 = fingerprint(plainBuffer);
  record.file = encryptFile(plainBuffer, record._id);
}

// Get the original PDF back out of a record (it must have been loaded with .select('+file'))
function readPdf(record) {
  return decryptFile(record.file, record._id, record.fileSha256);
}

module.exports = { fingerprint, getKey, encryptFile, decryptFile, storePdf, readPdf };
