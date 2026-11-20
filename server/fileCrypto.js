// Cryptography for stored PDFs (DECISIONS D38, D40): a SHA-256 fingerprint, a fresh session key per file,
// and AES-256-GCM encryption. Uses Node's built-in "crypto" module, so no extra package is needed.
const crypto = require('crypto');

// AES-GCM uses a 12-byte random "IV" (number used once) and produces a 16-byte authentication tag
const IV_BYTES = 12;
const TAG_BYTES = 16;
// AES-256 keys are 32 bytes (256 bits)
const KEY_BYTES = 32;

// 🔒 SECURITY 7.2.9 — SHA-256 fingerprint of a file: any change to the file gives a different fingerprint (OWASP A08)
// Returned as 64 hex characters. Students can compare it with their own copy
// (Windows: Get-FileHash file.pdf), so they can prove which exact file they handed in.
function fingerprint(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Read the 256-bit MASTER key from the settings (64 hex characters), or stop with a clear message.
// The master key never encrypts a file itself: it only wraps (encrypts) the per-file session keys.
function getMasterKey() {
  const hex = process.env.FILE_ENCRYPTION_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('FILE_ENCRYPTION_KEY must be 64 hex characters. Make one as shown in SETUP_GUIDE 6.9.');
  }
  return Buffer.from(hex, 'hex');
}

// AES-256-GCM encryption of some bytes. "label" (the record ID) is mixed into the tag as
// "additional data", so encrypted bytes copied into another record fail to decrypt.
// Result layout: [12-byte IV][16-byte tag][encrypted bytes]
function aesGcmEncrypt(key, plainBuffer, label) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(label)));
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

// AES-256-GCM decryption. final() throws "Unsupported state or unable to authenticate data"
// if even one byte was changed, the key is wrong, or the bytes belong to another record.
function aesGcmDecrypt(key, storedBuffer, label) {
  const iv = storedBuffer.subarray(0, IV_BYTES);
  const tag = storedBuffer.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const encrypted = storedBuffer.subarray(IV_BYTES + TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(String(label)));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// 🔒 SECURITY 7.3.10 — Session key generation: every upload gets its OWN fresh random AES-256 key (OWASP A02)
// The key is made from the operating system's secure random generator and used for this one file only.
// If one session key ever leaked, it would open one file, not all of them (Lecture 8: "limit exposure").
// 🔒 SECURITY 7.3.7 — The PDF is encrypted with AES-256-GCM before it reaches the database (OWASP A02)
// Atlas already encrypts its disks, but anyone who can read the database (a stolen DB password,
// a leaked backup, a database admin) would still see the PDFs. With this layer they only see random bytes.
function encryptFile(plainBuffer, recordId) {
  const sessionKey = crypto.randomBytes(KEY_BYTES);
  const file = aesGcmEncrypt(sessionKey, plainBuffer, recordId);
  // Key wrapping: the session key is stored next to the file, but only in encrypted form,
  // locked with the master key that lives in Render's settings (never in the database).
  const wrappedKey = aesGcmEncrypt(getMasterKey(), sessionKey, recordId);
  return { file, wrappedKey };
}

// 🔒 SECURITY 7.3.7 / 7.2.9 — Decrypt a stored PDF and prove it is unchanged before anyone gets it (OWASP A02, A08)
// Step 1: unwrap the session key with the master key. Step 2: decrypt the file with the session key.
// Step 3: the decrypted file must still have the fingerprint saved at upload time.
// Any failure throws, so the error handler logs it and the user gets a generic 500.
function decryptFile(file, wrappedKey, recordId, expectedSha256) {
  const sessionKey = aesGcmDecrypt(getMasterKey(), wrappedKey, recordId);
  const plain = aesGcmDecrypt(sessionKey, file, recordId);
  if (fingerprint(plain) !== expectedSha256) {
    throw new Error(`File integrity check failed for record ${recordId}`);
  }
  return plain;
}

// Put a freshly uploaded PDF into a submission or material record: fingerprint, encrypted file, wrapped key
function storePdf(record, plainBuffer) {
  const { file, wrappedKey } = encryptFile(plainBuffer, record._id);
  record.fileSha256 = fingerprint(plainBuffer);
  record.file = file;
  record.wrappedKey = wrappedKey;
}

// Get the original PDF back out of a record (it must have been loaded with .select('+file +wrappedKey'))
function readPdf(record) {
  return decryptFile(record.file, record.wrappedKey, record._id, record.fileSha256);
}

module.exports = { fingerprint, getMasterKey, encryptFile, decryptFile, storePdf, readPdf };
