# UniLearn security, explained

> **Status:** this file is being built. The **Cryptography** part (Lecture 8) is done. The other features (access control, uploads, Cloudflare, Clerk, logging…) are added in Phase 9, using the same layout.

---

## Cheat sheet (one screen)

| ID | Feature | Attack it stops | File:line |
|---|---|---|---|
| 7.2.9 ➕ | SHA-256 fingerprint on every PDF | "That's not the file I handed in", files changed after upload | `server/fileCrypto.js:9` |
| 7.3.7 ➕ | PDFs encrypted by the app (AES-256-GCM) | Reading student work from a leaked DB, backup or DB admin | `server/fileCrypto.js:25` |
| 7.3.7 ➕ | Tamper check on every download (GCM tag + fingerprint) | Swapping or editing a stored file in the DB | `server/fileCrypto.js:40` |
| 7.1.3 | Session token = digital signature (RSA) checked on every call | Forged or edited sign-in tokens | `server/middleware/auth.js:10` |
| 7.1.2 | HTTPS: TLS 1.2+, X.509 certificates, ECDHE key exchange | Eavesdropping, fake website (man-in-the-middle) | Cloudflare + Render (SETUP_GUIDE 7.5) |
| 7.3.3 | Atlas TLS + disk encryption | Reading data on the wire or from stolen disks | `server/db.js:20` |
| 7.4.1 | Origin secret compared via SHA-256 + constant time | Bypassing Cloudflare; guessing the secret by timing | `server/middleware/security.js:102` |
| — | Passwords stored as hashes by Clerk, never by us | Password theft from our database | Clerk (D3) |

➕ = extra, beyond the proposal (DECISIONS D38).

---

# Part A — Cryptography in UniLearn (Lecture 8)

## A0. Lecture 8 → UniLearn map

| Lecture topic | Where it lives in UniLearn | Section |
|---|---|---|
| Hash functions, file integrity (slides 3–8) | SHA-256 fingerprint of every PDF | A1 |
| Password verification by hashing (slide 7) | Clerk keeps only password hashes; we never see passwords | A6 |
| Symmetric encryption at rest, "app-level is the strongest layer" (slides 45–47) | AES-256-GCM on every PDF, before it reaches the DB | A2 |
| "Keys must NOT be stored alongside the data", key escrow (slides 29–30, 47) | Key only in Render settings + password-manager backup | A3 |
| HMAC / MAC (slides 9–11) | GCM's authentication tag; HMAC inside TLS (HKDF) | A2, A5 |
| Digital signatures with RSA (slides 13–16) | Clerk session tokens (JWT, RS256) | A4 |
| PKI, X.509, CA, certificate chain, revocation (slides 20–21, 36–43) | HTTPS certificates; Cloudflare "Full (strict)" checks Render's certificate | A5 |
| Key agreement, Diffie-Hellman, station-to-station, forward secrecy (slides 31–35) | TLS handshake with ephemeral (EC)DHE | A5 |
| Key derivation function (slide 23) | TLS 1.3 derives its session keys with HKDF | A5 |
| Database encryption / TDE (slide 46) | Atlas encryption at rest | A2 |

---

## A1. SHA-256 fingerprint (7.2.9 ➕)

### 🎯 What
Every uploaded PDF gets a **SHA-256 fingerprint**: 64 hex characters, always the same length, whatever the file size. Change **one byte** of the file and the fingerprint is completely different.

### 😈 The attack
- A student says: "I handed in the right file, your system changed it."
- Someone with database access swaps a submission after the deadline.
- An upload gets corrupted on the way.

### 🛡️ How my code stops it
1. On upload, the server hashes the PDF and saves `fileSha256` next to it.
2. The **browser** hashes the same file itself (Web Crypto) and compares it with the server's answer: "✔ The server received exactly your file".
3. On every download, the server hashes the decrypted file again. If it differs from `fileSha256`, the download is refused.
4. The student can check their own copy: `Get-FileHash file.pdf` in PowerShell gives the same 64 characters.

### 📍 Where
`server/fileCrypto.js:9`
```js
// 🔒 SECURITY 7.2.9 — SHA-256 fingerprint of a file
function fingerprint(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}
```
`client/src/Submissions.jsx:37`
```js
const localSha256 = await sha256Of(file);
const receipt = await callApi(getToken, `${address}/mine`, 'PUT', formData);
setReceiptCheck(receipt.fileSha256 === localSha256 ? 'match' : 'mismatch');
```

### 🗣️ Say this in the discussion
"A hash is a one-way, fixed-length fingerprint. I store the SHA-256 of every PDF, show it to the student as a receipt, and recheck it on every download. That gives **integrity**: if anyone changes the file, the fingerprints stop matching. A hash alone doesn't prove *who* made a change. In my system that comes from the access checks and the audit log."

---

## A2. App-level encryption with AES-256-GCM (7.3.7 ➕)

### 🎯 What
Before a PDF is saved, **our server encrypts it** with AES-256 in GCM mode. The database only ever holds random-looking bytes. This sits **on top of** Atlas's own disk encryption (7.3.3).

### 😈 The attack
Atlas disk encryption only helps if someone steals a physical disk. It does **not** help if someone:
- gets the database password (leaked `.env`, screenshot, phishing);
- gets a database backup;
- is a database administrator (insider).

All of them would read every student's work. Lecture 8 (slide 46): application-level encryption is "the strongest layer (avoids insider DBA attacks)".

### 🛡️ How my code stops it
- **AES-256**: symmetric, 256-bit key, the industry standard (slide 47).
- **GCM mode** = encryption **plus** an authentication tag, which works like a MAC (slide 9). If even one stored byte is changed, decryption **fails** instead of returning garbage.
- A fresh random **IV** (12 bytes) for every file, so the same PDF uploaded twice never looks the same.
- The record's own ID goes into the tag (GCM "additional data"). Copying one student's encrypted file into another student's record makes the check fail.
- Stored layout: `[IV 12 bytes][tag 16 bytes][encrypted PDF]`.

### 📍 Where
`server/fileCrypto.js:33`
```js
const iv = crypto.randomBytes(IV_BYTES);
const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
cipher.setAAD(Buffer.from(String(recordId)));
const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
```
`server/fileCrypto.js:50`
```js
decipher.setAuthTag(tag);
// final() throws if the tag doesn't match
const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
if (fingerprint(plain) !== expectedSha256) {
  throw new Error(`File integrity check failed for record ${recordId}`);
}
```

### 🗣️ Say this in the discussion
"Atlas encrypts its disks, but that's like locking the building while the filing cabinet stays open: anyone with the database password still reads everything. So my server encrypts each PDF with AES-256-GCM **before** saving it. GCM also authenticates the data, so a changed byte is detected, not silently accepted. The key never touches the database."

---

## A3. Where the key lives (7.3.7 ➕, 7.2.8)

### 🎯 What
`FILE_ENCRYPTION_KEY`: 32 random bytes (256 bits), written as 64 hex characters.

### 😈 The attack
If the key sat in the database or in GitHub, stealing the data would also steal the key, and the encryption would be worthless.

### 🛡️ How my code stops it
- The key lives **only** in `server/.env` (ignored by Git) and in **Render's settings**: never in the DB, never in the code (slide 47: "Keys must NOT be stored alongside the encrypted data").
- The server **refuses to start** without a valid 256-bit key, so it can never run "half-encrypted".
- **Key escrow / backup:** a copy is kept in my password manager (slides 29–30). If the key were lost, every PDF would be unreadable.
- It's random, not made from a password, so no key-derivation function is needed.

### 📍 Where
`server/fileCrypto.js:17`
```js
function getKey() {
  const hex = process.env.FILE_ENCRYPTION_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('FILE_ENCRYPTION_KEY must be 64 hex characters. ...');
  }
  return Buffer.from(hex, 'hex');
}
```

### 🗣️ Say this in the discussion
"The data is in Atlas and the key is in Render: two different companies, two different logins. To read a PDF, an attacker needs both. A real university would put the key in a KMS or HSM. That's my honest limitation."

---

## A4. Digital signatures: the sign-in token (7.1.3)

### 🎯 What
After sign-in, Clerk gives the browser a **session token** (a JWT). Clerk **signs** it with its **private RSA key**. On every API call, our server checks the signature with Clerk's **public key**.

### 😈 The attack
A student edits their token to say they're someone else, or makes up a token.

### 🛡️ How my code stops it
This is exactly slide 16 ("Signing messages with RSA"): hash the token, sign the hash with the private key, verify with the public key. Change one character of the token and verification fails, so the server answers 401. `authorizedParties` also rejects tokens made for another website. The role is **never** taken from the token. It comes from our own database.

### 📍 Where
`server/middleware/auth.js:10`
```js
// Reads the Clerk session token sent with each request and checks its signature.
const readClerkSession = clerkMiddleware({ authorizedParties: allowedOrigins });
```

### 🗣️ Say this in the discussion
"The session token is digitally signed by Clerk. Only Clerk has the private key, and my server verifies it with the public key. That gives authenticity and integrity: nobody can forge or edit a token. It's the same RSA signing as slide 16."

---

## A5. HTTPS: PKI, certificates, key agreement (7.1.2)

### 🎯 What
Every page and API call goes over **TLS 1.2 or newer**, twice: browser → Cloudflare, and Cloudflare → Render.

### 😈 The attack
Someone on the same Wi-Fi reads grades or steals session tokens, or sets up a fake "UniLearn" in the middle.

### 🛡️ How it stops it (configuration, not my code)
- **PKI / X.509 (slides 36–43):** the site's certificate binds the name `unilearn-omar.com` to a public key and is signed by a **CA**. The browser checks the chain up to a root CA it already trusts, the expiry date, and revocation.
- **Full (strict)** in Cloudflare: Cloudflare does the same checks on **Render's** certificate, so the hidden second hop can't be faked either.
- **Key agreement (slides 31–35):** the TLS handshake uses **ephemeral Diffie-Hellman (ECDHE)**, signed with the server's certificate key. That's the station-to-station idea: DH for the key, signatures so nobody can sit in the middle.
- **Perfect forward secrecy (slide 33):** each session's key is thrown away, so a server key stolen later can't decrypt recorded traffic.
- **KDF + HMAC (slides 9, 23):** TLS 1.3 derives its session keys with **HKDF**, which is built on HMAC-SHA-256. The data then travels in AES-GCM.
- **HSTS** (helmet) tells browsers to always use HTTPS.

### 📍 Where
Cloudflare → SSL/TLS: **Full (strict)**, **Always Use HTTPS**, **Minimum TLS 1.2** (SETUP_GUIDE 7.5). HSTS: `server/middleware/security.js:17`.

### 🗣️ Say this in the discussion
"HTTPS is the whole of Lecture 8 in one place: certificates and a CA chain for authenticity, ephemeral Diffie-Hellman for the session key with forward secrecy, HMAC-based key derivation, and AES-GCM for the data. I can show it live: padlock → certificate → certification path, and DevTools → Security shows the TLS version and key exchange."

---

## A6. What I deliberately don't do myself

| Thing | Who does it | Why that's safer |
|---|---|---|
| Password hashing | Clerk (slow, salted hash; we never receive passwords) | One less secret store for us to lose (D3) |
| Session keys for HTTPS | Cloudflare + Render (TLS) | Proven libraries, automatic certificate renewal |
| Disk encryption | Atlas (encryption at rest by default) | The cloud provider manages the disk keys |
| Package integrity | npm checks the SHA-512 `integrity` hash of every package in `package-lock.json` | A changed package fails to install |

**Rule I followed:** use standard algorithms from Node's built-in `crypto` (AES-256-GCM, SHA-256), never invent my own cipher.

---

## A7. Likely examiner questions (cryptography)

1. **Why encrypt the PDFs if Atlas already encrypts at rest?** Atlas protects the disks. My layer protects against anyone who can *query* the database: a leaked password, a backup, an insider.
2. **Why GCM and not CBC?** GCM also authenticates the data (it has a built-in tag, like a MAC), so tampering is detected. CBC alone would decrypt changed data into garbage without noticing.
3. **What is the IV, and why random?** A number used once. With a new random IV, the same file never encrypts to the same bytes, and GCM's security depends on never reusing an IV with the same key.
4. **What's the difference between your hash and your encryption?** The hash is one-way and public (integrity: "is this the same file?"). Encryption is reversible with the key (confidentiality: "who can read it?").
5. **Hash vs HMAC vs digital signature?** A hash has no key. An HMAC uses a shared secret key (both sides can create it). A signature uses a private key, so only one party can create it, which gives non-repudiation (slides 9, 13).
6. **Where is the key, and what if it's lost?** Render settings + my `.env`, backed up in a password manager (escrow). If it's lost, the PDFs are lost. That's why the backup exists.
7. **What if the key leaks?** The attacker still needs the database too. I'd have to re-encrypt with a new key. Rotation isn't built yet: a stated limitation.
8. **Can a student cheat by swapping files in the DB?** They have no DB access. Even an admin who does can't move an encrypted file to another record (record ID in the GCM tag) or edit it (tag + fingerprint fail).
9. **How does the browser know the site is really UniLearn?** The X.509 certificate chain up to a trusted root CA (slides 40–42).
10. **What gives forward secrecy here?** Ephemeral (EC)DHE in TLS. Each session key is new and discarded.
11. **Why doesn't your database store passwords?** Clerk does sign-in and stores only hashes. We never receive a password.

---

## A8. Live demo script (cryptography, about 3 minutes)

1. **Receipt:** sign in as a student → upload a PDF → point at "✔ The server received exactly your file". Open the SHA-256 line.
2. **Same hash locally:** PowerShell `Get-FileHash .\file.pdf` → the same 64 characters.
3. **Encrypted in the DB:** Atlas → Data Explorer → `submissions` → the `file` field is unreadable binary, with no `%PDF-` at the start.
4. **Still works for the right people:** download it on the site → a normal PDF.
5. **Signed token:** DevTools → Network → any `/api` call → `Authorization: Bearer eyJ…` → "this is RSA-signed by Clerk; change one letter and the server says 401".
6. **HTTPS:** padlock → certificate → the issuer and chain; DevTools → **Security** tab → TLS version and key exchange (e.g. X25519).

---

## A9. Honest limitations (cryptography)

1. **No key rotation yet:** changing the key needs a re-encrypt script (future work).
2. **Key in an environment variable, not a KMS/HSM:** fine for a course project; a university would use a cloud KMS.
3. **Only the PDFs are app-encrypted:** names, emails and grades rely on Atlas encryption + access control.
4. **Admins can't verify a student's file themselves:** by design they have no access to student work (D37). The instructor sees the fingerprint.
5. **Development Clerk instance (D17):** fine for signing tokens, but not meant for real students.
