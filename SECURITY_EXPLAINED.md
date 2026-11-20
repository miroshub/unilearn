# UniLearn security, explained

> **Status:** this file is being built. The **Cryptography** part (Lecture 8) is done. The other features (access control, uploads, Cloudflare, Clerk, logging…) are added in Phase 9, using the same layout.

---

## Cheat sheet (one screen)

| ID | Feature | Attack it stops | File:line |
|---|---|---|---|
| 7.2.9 ➕ | SHA-256 fingerprint on every PDF | "That's not the file I handed in", files changed after upload | `server/fileCrypto.js:11` |
| 7.3.7 ➕ | PDFs encrypted by the app (AES-256-GCM) | Reading student work from a leaked DB, backup or DB admin | `server/fileCrypto.js:54` |
| 7.3.10 ➕ | Session key generation: a new AES key per file, wrapped by the master key | One leaked key opening every file | `server/fileCrypto.js:51` |
| 7.3.8 ➕ | Digital signatures (RSA-PSS) on receipts and grades | Grades edited in the DB; the university denying it received a file | `server/pki.js:54` |
| 7.3.9 ➕ | Own PKI: Root CA → X.509 signing certificate, checked at startup | Fake, expired or mismatched certificate/key | `server/pki.js:15` |
| 7.1.3 | Clerk's signed session token (RSA), checked on every call | Forged or edited sign-in tokens | `server/middleware/auth.js:10` |
| 7.1.2 | HTTPS: TLS 1.2+, X.509 certificates, ECDHE session keys | Eavesdropping, fake website (man-in-the-middle) | Cloudflare + Render (SETUP_GUIDE 7.5) |
| 7.3.3 | Atlas TLS + disk encryption | Reading data on the wire or from stolen disks | `server/db.js:20` |
| — | Passwords stored as hashes by Clerk, never by us | Password theft from our database | Clerk (D3) |

➕ = extra, beyond the proposal (DECISIONS D38, D40).

---

# Part A — Cryptography in UniLearn (Lecture 8)

## A0. Lecture 8 → UniLearn map

| Lecture topic | In UniLearn's own code | Also used by our providers | Section |
|---|---|---|---|
| **Encryption algorithms** (slide 47) | AES-256-GCM (files, key wrapping), SHA-256, RSA-3072 / RSA-PSS | TLS: AES-GCM, ECDHE | A1–A5 |
| **Hash functions, file integrity** (slides 3–8) | SHA-256 fingerprint of every PDF | npm `integrity` hashes | A1 |
| **Session keys** (slides 31–33) | A fresh AES-256 key per uploaded file, wrapped by the master key | TLS session keys (ECDHE) | A3 |
| **Key storage, key wrapping, key escrow** (slides 29–30, 47) | Master key + signing key only in Render settings; root CA key offline; password-manager backup | — | A4 |
| **MAC / HMAC** (slides 9–11) | GCM authentication tag on every file and wrapped key | HKDF (HMAC) in TLS 1.3 | A2, A7 |
| **Digital signatures** (slides 13–16) | RSA-PSS signatures on submission receipts and grades, verified by server and browser | Clerk session tokens (RS256) | A5 |
| **Certificates, CA, X.509, chain** (slides 20–21, 36–42) | UniLearn Root CA issues the signing certificate; checked at startup | HTTPS certificate, Cloudflare Full (strict) | A6, A7 |
| **Key agreement, Diffie-Hellman, forward secrecy** (slides 31–35) | — | TLS handshake (ECDHE) | A7 |
| **Data at rest, database encryption** (slides 45–46) | App-level encryption (strongest layer) | Atlas encryption at rest | A2 |

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
`server/fileCrypto.js:14`
```js
function fingerprint(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}
```

### 🗣️ Say this in the discussion
"A hash is a one-way, fixed-length fingerprint. I store the SHA-256 of every PDF, show it to the student, and recheck it on every download. That gives **integrity**: if anyone changes the file, the fingerprints stop matching."

---

## A2. AES-256-GCM encryption at rest (7.3.7 ➕)

### 🎯 What
Before a PDF is saved, **our server encrypts it** with **AES-256 in GCM mode**. The database only ever holds random-looking bytes. This sits **on top of** Atlas's own disk encryption (7.3.3).

### 😈 The attack
Atlas disk encryption only helps if someone steals a physical disk. It does **not** help if someone gets the database password (a leaked `.env`, a screenshot, phishing), gets a backup, or is a database administrator. Lecture 8 (slide 46): application-level encryption is "the strongest layer (avoids insider DBA attacks)".

### 🛡️ How my code stops it
- **AES-256**: symmetric, 256-bit key, the industry standard (slide 47).
- **GCM mode** = encryption **plus** an authentication tag, which works like a MAC (slide 9). Change one stored byte and decryption **fails** instead of returning garbage.
- A fresh random **IV** (12 bytes) every time, so the same PDF never encrypts to the same bytes.
- The record's own ID goes into the tag ("additional data"). Copying one student's encrypted file into another record makes the check fail.

### 📍 Where
`server/fileCrypto.js:31`
```js
function aesGcmEncrypt(key, plainBuffer, label) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(label)));
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}
```

### 🗣️ Say this in the discussion
"Atlas encrypts its disks, but anyone with the database password could still read everything. So my server encrypts each PDF with AES-256-GCM **before** saving it. GCM also authenticates the data, so a changed byte is detected, not silently accepted."

---

## A3. Session key generation (7.3.10 ➕)

### 🎯 What
Every upload gets its **own brand-new AES-256 key** (the session key), made from the operating system's secure random generator. That key encrypts **this one file only**. The session key is then **wrapped**: encrypted with the long-term **master key** and stored next to the file as `wrappedKey`.

```
master key (Render settings) ──wraps──► session key #1 ──encrypts──► PDF #1
                             ──wraps──► session key #2 ──encrypts──► PDF #2
```

### 😈 The attack
With one key for everything, a single leaked key opens **every** file, and a lot of ciphertext piles up under one key for cryptanalysis (slide 31).

### 🛡️ How my code stops it
- **Fresh per file:** the same PDF uploaded twice gets two different keys and two different stored bytes (tested).
- **Limited exposure:** a leaked session key opens one file (slide 31: "limit exposure caused by the compromise of a session key").
- **Key transport / key wrapping (slides 32, 47):** the master key is only used to transport the session keys, never to encrypt a file.
- **Master key alone can't read a file:** you must unwrap first, then decrypt (tested).
- **Easier rotation:** changing the master key would only mean re-wrapping the small keys, not re-encrypting the PDFs.

### 📍 Where
`server/fileCrypto.js:57`
```js
function encryptFile(plainBuffer, recordId) {
  const sessionKey = crypto.randomBytes(KEY_BYTES);
  const file = aesGcmEncrypt(sessionKey, plainBuffer, recordId);
  // Key wrapping: the session key is stored, but only locked with the master key
  const wrappedKey = aesGcmEncrypt(getMasterKey(), sessionKey, recordId);
  return { file, wrappedKey };
}
```

### 🗣️ Say this in the discussion
"Every upload generates its own 256-bit session key with a secure random generator. That key encrypts the file, and is itself encrypted with the master key. This is key wrapping, like key transport in the lecture. One compromised session key exposes one file, not the whole system."

---

## A4. Where the keys live (7.3.7, 7.3.8, 7.3.9, 7.2.8)

| Key | What it does | Where it lives | Backup |
|---|---|---|---|
| Master key `FILE_ENCRYPTION_KEY` (AES-256) | Wraps the session keys | Render settings + `server/.env` | Password manager |
| Session keys (AES-256, one per file) | Encrypt one PDF each | In the DB, **only wrapped** | Not needed (wrapped) |
| Signing private key `SIGNING_PRIVATE_KEY` (RSA-3072) | Signs receipts and grades | Render settings + `server/.env` | Password manager |
| Root CA private key (RSA-3072) | Issued the signing certificate | **Offline** on my PC, never on the server | Password manager |
| Certificates (public) | Let anyone check signatures | `server/pki/` in GitHub | Not secret |

- Slide 47: "Keys must NOT be stored alongside the encrypted data". The data is in Atlas; the keys are in Render.
- Slides 29–30, **key escrow**: the password-manager copies are the recovery path. A lost master key means every PDF is lost.
- The server **refuses to start** if a key is missing, malformed or doesn't match its certificate (fail closed).

### 🗣️ Say this in the discussion
"The data is in Atlas and the keys are in Render: two different companies, two different logins. The root CA key isn't on any server at all. A real university would use a KMS or HSM; that's my honest limitation."

---

## A5. Digital signatures (7.3.8 ➕)

### 🎯 What
UniLearn has its own **RSA-3072 key pair**. The server **signs** two things with the private key:
1. **Submission receipts:** submission, assignment, student, the file's SHA-256, the time.
2. **Grades:** grade, assignment, student, score, who graded, when.

Anyone can **verify** a signature with the public key from UniLearn's certificate: the server, the browser, or OpenSSL.

### 😈 The attack
- Someone with database access changes a score from 45 to 85. Without a signature, nobody would notice.
- A dispute: "UniLearn never received my file", or the reverse, "the student made this receipt up".

### 🛡️ How my code stops it
Exactly slide 16 ("Signing messages with RSA"):
1. Hash the text with SHA-256.
2. Sign the hash with the **private** key (RSA-PSS, modern RSA padding).
3. The receiver hashes the text again and checks the signature with the **public** key.

- **Grades are re-checked every time they are shown.** A score edited in the DB shows **⚠ signature invalid** in the grade book and the student's view, and Render logs `WARN Grade signature check failed`.
- **Receipts:** the student clicks **Verify signature**, and **their browser** checks it with Web Crypto. It doesn't just trust the server's word.
- **Properties (slides 13–14):** authenticity (only UniLearn has the private key), integrity (one changed character breaks it), non-repudiation (UniLearn can't deny issuing the receipt).

### 📍 Where
`server/pki.js:57`
```js
function signText(text) {
  return crypto.sign('sha256', Buffer.from(text), { key: getIdentity().privateKey, ...SIGN_OPTIONS })
    .toString('base64');
}
```
`server/routes/grades.js:96`
```js
grade.signature = signText(gradeText(grade));
```
`client/src/api.js:52` (in the browser)
```js
const publicKey = await crypto.subtle.importKey('spki', base64ToBytes(publicKeySpki),
  { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
return crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, publicKey, base64ToBytes(signature),
  new TextEncoder().encode(text));
```

### 🗣️ Say this in the discussion
"Every grade and every submission receipt is digitally signed with UniLearn's private RSA key. If anyone edits a grade directly in the database, the signature no longer matches and the system flags it. The student's browser can verify a receipt itself with the public key from our certificate. That gives authenticity, integrity and non-repudiation. Sign-in uses signatures too: Clerk's session tokens are RSA-signed and checked on every request."

---

## A6. Certificates and our own CA (7.3.9 ➕)

### 🎯 What
A **public key alone proves nothing**: anyone can make a key pair and claim it's UniLearn's (slide 36, "Eve"). So UniLearn has a small **PKI**:

```
UniLearn Root CA (self-signed, CA:TRUE, 5 years, private key OFFLINE)
   └── issues ──► UniLearn Signing Service (X.509, CA:FALSE, digitalSignature only, 1 year)
                     └── its key signs receipts and grades
```

Made once with **OpenSSL** by `server/scripts/make-pki.sh`.

### 😈 The attack
- Swapping in a fake certificate, even one with the same name ("UniLearn Root CA" made by an attacker).
- Using an expired certificate.
- Running the server with a private key that doesn't belong to the certificate.

### 🛡️ How my code stops it
At startup the server checks the certificate exactly as slide 40 says, and **refuses to start** if any check fails:
1. The root is a real CA and its self-signature is valid.
2. The signing certificate was **issued by** our root **and** its signature verifies with the root's public key. That's the chain (slides 41–42).
3. **Not expired** and already valid (both certificates).
4. The private key in the settings **matches** the certificate.

All four bad cases above were tested and refused. `GET /api/pki` gives the certificates and public key to signed-in users, so anyone can check a signature.

### 📍 Where
`server/pki.js:29`
```js
if (!rootCa.ca || !rootCa.verify(rootCa.publicKey)) { throw … }
if (signingCert.ca || !signingCert.checkIssued(rootCa) || !signingCert.verify(rootCa.publicKey)) { throw … }
for (const cert of [rootCa, signingCert]) { /* validFrom ≤ now ≤ validTo */ }
if (!signingCert.checkPrivateKey(privateKey)) { throw … }
```

### 🗣️ Say this in the discussion
"I built a small PKI with OpenSSL: a UniLearn Root CA issues an X.509 certificate for the signing key. At startup my server verifies the chain, the dates and that the key matches, which are the verification steps from the lecture. The root CA's private key never touches the server, so even a hacked server can't issue new certificates."

---

## A7. HTTPS: certificates and session keys on the wire (7.1.2)

### 🎯 What
Every page and API call goes over **TLS 1.2 or newer**, twice: browser → Cloudflare, and Cloudflare → Render.

### 😈 The attack
Someone on the same Wi-Fi reads grades or steals session tokens, or sets up a fake "UniLearn" in the middle.

### 🛡️ How it stops it (configuration, not my code)
- **X.509 certificate + CA chain:** the browser checks that `unilearn-omar.com`'s certificate chains to a root it trusts, isn't expired, and isn't revoked.
- **Full (strict):** Cloudflare does the same checks on **Render's** certificate.
- **Session keys by key agreement (slides 31–35):** the TLS handshake uses **ephemeral Diffie-Hellman (ECDHE)**, signed with the server's certificate key. That's the station-to-station idea.
- **Perfect forward secrecy (slide 33):** each session key is thrown away; a server key stolen later can't decrypt recorded traffic.
- **KDF + HMAC (slides 9, 23):** TLS 1.3 derives its keys with **HKDF** (built on HMAC-SHA-256), then sends data with AES-GCM.

### 🗣️ Say this in the discussion
"My own code does key **transport**: the master key wraps per-file session keys. HTTPS does key **agreement**: ephemeral Diffie-Hellman with forward secrecy. Together they cover both kinds of session key establishment from the lecture."

---

## A8. What I deliberately don't do myself

| Thing | Who does it | Why that's safer |
|---|---|---|
| Password hashing | Clerk (slow, salted hash; we never receive passwords) | One less secret store for us to lose (D3) |
| HTTPS certificates and TLS session keys | Cloudflare + Render | Automatic renewal, proven libraries |
| Disk encryption | Atlas (default) | The provider manages the disk keys |
| Package integrity | npm checks the SHA-512 `integrity` hash in `package-lock.json` | A changed package fails to install |

**Rule I followed:** only standard algorithms from Node's built-in `crypto` and OpenSSL (AES-256-GCM, SHA-256, RSA-PSS). Never my own cipher.

---

## A9. Likely examiner questions (cryptography)

1. **Which encryption algorithms do you use, and for what?** AES-256-GCM for files and for wrapping session keys; SHA-256 for fingerprints and inside signatures; RSA-3072 with PSS padding for signatures; TLS (AES-GCM + ECDHE) on the network.
2. **What is a session key in your system?** A fresh random AES-256 key per uploaded file, used once, stored only encrypted with the master key.
3. **Why not encrypt everything with the master key?** One leaked key would open every file, and more data under one key helps cryptanalysis. Session keys limit both (slide 31).
4. **Why GCM and not CBC?** GCM also authenticates (built-in tag, like a MAC), so tampering is detected.
5. **What does your digital signature prove?** That UniLearn issued exactly this grade or receipt (authenticity), that it hasn't changed (integrity), and that UniLearn can't deny it (non-repudiation).
6. **Hash vs HMAC vs signature?** A hash has no key. An HMAC uses one shared secret (both sides can make it). A signature uses a private key only one party has, and anyone can verify it with the public key.
7. **Why do you need a certificate if you have a public key?** Anyone can make a key pair and claim it's UniLearn's. The CA's signature binds the key to the name (slide 36).
8. **How does your server verify the certificate?** It checks the CA signature on it, the validity dates, that the issuer is our root, and that the private key matches (slide 40).
9. **Why keep the root CA key offline?** If the server were hacked, the attacker still couldn't issue new trusted certificates.
10. **What if the signing key leaks?** Make a new PKI and re-sign. There's no revocation list (CRL), which is a stated limitation.
11. **Does the instructor personally sign grades?** No, UniLearn signs. Who changed what is proven by MFA sign-in plus the audit log.
12. **Where is forward secrecy?** In TLS (ephemeral ECDHE). My file session keys don't need it: they are stored, wrapped.
13. **Why RSA-PSS and not plain RSA?** PSS adds random padding and has a security proof; it's the recommended RSA signature scheme.

---

## A10. Live demo script (cryptography, about 5 minutes)

1. **Certificates:** in Explorer, double-click `server\pki\unilearn-signing.crt` → **Certification Path**: UniLearn Root CA → UniLearn Signing Service. The **Details** tab shows the X.509 fields (version, serial, validity, public key, key usage).
2. **Startup check:** Render logs show `Signing certificate OK`.
3. **Upload + fingerprint:** as a student, upload a PDF → "✔ The server received exactly your file". PowerShell `Get-FileHash` gives the same SHA-256.
4. **Signature in the browser:** open **Signed receipt** → **Verify signature** → "✔ Valid RSA signature by UniLearn Signing Service, issued by UniLearn Root CA".
5. **Encryption + session keys:** Atlas → `submissions` → `file` and `wrappedKey` are unreadable; there's no `%PDF-`. Download on the site → a normal PDF.
6. **Tamper a grade:** as the instructor, grade the work (85). In Atlas, edit that grade's `score` to 100. Refresh the grade book → **⚠ signature invalid**; Render logs `WARN Grade signature check failed`. Put it back to 85 → ✔ signed.
7. **HTTPS:** padlock → certificate chain of the live site; DevTools → **Security** → TLS version and ECDHE key exchange.

---

## A11. Honest limitations (cryptography)

1. **The server signs, not each instructor personally.** Instructor accountability comes from MFA + the audit log.
2. **No revocation (CRL/OCSP)** for our own certificates. A compromised signing key means making a new PKI.
3. **Trust in our root:** the browser gets the public key from the same server. For full trust, compare the root CA's SHA-256 fingerprint with the published one.
4. **Keys in environment variables, not a KMS/HSM.** Fine for a course project; a university would use a cloud KMS.
5. **No master-key rotation script yet.** With session keys it would only need a re-wrap.
6. **Only the PDFs are app-encrypted.** Names, emails and grades rely on Atlas encryption + access control (grades are signed, not encrypted).
7. **Development Clerk instance (D17).**
