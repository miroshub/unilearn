# Security ID map

The IDs follow proposal §7, numbering the rows of each table in order. Use them in code tags, like `// 🔒 SECURITY 7.2.2 — …`, and in the cheat sheet in `SECURITY_EXPLAINED.md`.

**Kind** says where each measure lives:
- **code:** tagged in the source.
- **config:** a dashboard setting, documented in `SETUP_GUIDE.md`.
- **process:** something people do, documented in the docs.

Fill in **Where** as each measure is built.

| ID | Measure | Stops | OWASP | Kind | Where |
|---|---|---|---|---|---|
| **7.1 Front end** | | | | | |
| 7.1.1 | User text shown only through React's normal output; no raw HTML | XSS | A03 Output Encoding | code | `client/src/HomePage.jsx:56` (no `dangerouslySetInnerHTML` anywhere) |
| 7.1.2 | HTTPS on every page (Render + Cloudflare) | Eavesdropping, session theft | A02 Communication Security | config | Cloudflare Always Use HTTPS + SSL Full (strict) + minimum TLS 1.2 (SETUP_GUIDE 7.5); HSTS header from helmet `server/middleware/security.js:17` |
| 7.1.3 | Sessions handled by Clerk; tokens never in localStorage | Session theft | A07 Session Management | code | Token checked: `server/middleware/auth.js:7`; token fetched per call, never stored: `client/src/HomePage.jsx:14`; 30 min / 8 h limits in Clerk (SETUP_GUIDE 5.8) |
| 7.1.4 | No secret keys in front-end code (only the publishable key) | Leaked keys | A05 System Configuration | code | `client/src/main.jsx:8`; secret key only in `server/.env` |
| 7.1.5 | Buttons hidden by role for clarity only; the server still checks | Users trying hidden features | A01 Access Control | code | |
| **7.2 Back end** | | | | | |
| 7.2.1 | Sign-in check on every route | Anonymous access | A07 Authentication | code | `server/middleware/auth.js:42` (`requireSignIn`) |
| 7.2.2 | Role + ownership check on every route | Changing grades, seeing others' data | A01 Access Control | code | |
| 7.2.3 | Request data checked against a schema; unknown fields rejected | Malicious input, self-assigned roles | A03 Input Validation | code | `server/models/*.js:4` (`strict: 'throw'` on all 8 schemas); per-route checks added with each route |
| 7.2.4 | Limit on requests per minute | Flooding, password guessing | A04, A07 | code | `server/middleware/security.js:35`; counts the real visitor IP behind Cloudflare: `server/app.js:21` (`trust proxy`, proven in SETUP_GUIDE 7.10) |
| 7.2.5 | Security headers; API accepts calls only from the UniLearn website | Clickjacking, cross-site calls | A05 System Configuration | code | Headers: `server/middleware/security.js:17`; origin check: `server/middleware/security.js:54` |
| 7.2.6 | Uploads: PDF only, max 10 MB | Harmful files | A04 File Management | code | |
| 7.2.7 | Generic error message to users; details go to the logs | Leaking internals | A05 Error Handling | code | `server/middleware/errors.js:32` |
| 7.2.8 | Secrets in Render settings; `.env` never in GitHub | Leaked keys | A02, A05 | code + config | `.gitignore:4`, `server/.env.example`; GitHub push protection (SETUP_GUIDE 3.3) |
| **7.3 Database** | | | | | |
| 7.3.1 | Atlas IP access list allows only Render's outbound IPs | Direct DB attacks | A05 Database Security | config | Atlas IP access list = Render's outbound IP ranges only (SETUP_GUIDE 6.4) |
| 7.3.2 | App DB user: readWrite on the UniLearn DB only, long generated password | Full takeover if the password leaks | A01, A07 | config | Atlas DB user (SETUP_GUIDE 4.3); `dbName` in `server/db.js:17` |
| 7.3.3 | Encryption in transit (TLS) and at rest (Atlas default) | Data read in transit or from disk | A02 Data Protection | config | `tls: true` in `server/db.js:19`; at rest = Atlas default (SETUP_GUIDE 4.6) |
| 7.3.4 | Query filters cleaned; data shapes fixed by Mongoose schemas | NoSQL injection | A03 Database Security | code | `$` keys refused: `server/middleware/security.js:82`; `strictQuery: 'throw'`: `server/models/*.js:4` |
| 7.3.5 | Only data needed for teaching is stored | Size of any breach | A02 Data Protection | code | |
| 7.3.6 | Weekly database backup | Data loss | Recovery | process | |
| **7.4 Network and hosting** | | | | | |
| 7.4.1 | All traffic through the Cloudflare WAF; Always Use HTTPS | DDoS, bots, web attacks | — | config | Cloudflare proxy + free managed WAF rules (SETUP_GUIDE 7.6, 7.7); secret header from Cloudflare required: `server/middleware/security.js:107` (SETUP_GUIDE 7.8); `onrender.com` address disabled (SETUP_GUIDE 7.11) |
| 7.4.2 | Database accepts connections only from Render (see 7.3.1) | Direct DB attacks | — | config | Same as 7.3.1 (SETUP_GUIDE 6.4) |
| 7.4.3 | Render manages OS updates, server firewall, physical security (shared responsibility) | Unpatched or exposed servers | — | config | Render web service, no server of our own to patch (SETUP_GUIDE 6.8) |
| 7.4.4 | 2FA on the GitHub, Render, Atlas, Clerk and Cloudflare accounts | Takeover of control accounts | — | process | Checklist for GitHub, Render, Atlas, Clerk, Cloudflare, UptimeRobot (SETUP_GUIDE 8.3) |
| 7.4.5 | Dependabot + `npm audit` on every push | Vulnerable packages | A06 | config | `.github/workflows/security-audit.yml`, `.github/dependabot.yml` |
| 7.4.6 | Render deploys only from `main` | Unfinished code going live | — | config | Render: branch `main`, Auto-Deploy only after GitHub checks pass (SETUP_GUIDE 6.6) |
| **7.5 Users** | | | | | |
| 7.5.1 | MFA required for admins and instructors | Phishing / account takeover | A07 | code + config | `server/middleware/auth.js:65`; TOTP + backup codes in Clerk (SETUP_GUIDE 5.6) |
| 7.5.2 | Minimum password length; breached passwords rejected | Weak or reused passwords | A07 | config | Clerk: minimum length 12, compromised passwords rejected (SETUP_GUIDE 5.5) |
| 7.5.3 | Automatic blocking after repeated failed sign-ins | Password guessing | A07 | config | Clerk Protect: lockout after 5 attempts for 15 min (SETUP_GUIDE 5.7) |
| 7.5.4 | No public sign-up; admins invite by university email | Fake accounts | A07 | code + config | Clerk Access mode = Invite-only (SETUP_GUIDE 5.4); `server/scripts/addUser.js:22`; no-account refusal `server/middleware/auth.js:55` |
| 7.5.5 | Accounts disabled when people leave | Former users keeping access | A01 | code | `server/middleware/auth.js:60`; `status` field `server/models/User.js:15` |
| 7.5.6 | One-page security tips guide for users | Phishing, sharing codes | — | process | |
| **7.6 Logging** | | | | | |
| 7.6.1 | Audit log: grade changes (old + new), role changes, account creation/removal | Untraceable changes (repudiation) | A09 | code | Collection: `server/models/AuditLog.js:1` (entries written from Phase 4) |
| 7.6.2 | Application log: denied access, errors, blocked requests (Render logs) | Unnoticed attacks | A09 | code | `server/logger.js:38`; called from `server/middleware/security.js` and `errors.js` |
| 7.6.3 | Sign-in log: sign-ins, failures, MFA events (Clerk dashboard) | Unnoticed account attacks | A09 | config | Clerk dashboard → Logs, and Users → a user → sessions |
| 7.6.4 | Attack log: blocked requests, bot traffic (Cloudflare) | Unnoticed attacks | A09 | config | Cloudflare → Security → Events (SETUP_GUIDE 8.2) |
| 7.6.5 | Deployment log: pushes, checks, deploys (GitHub + Render) | Untraceable releases | A09 | config | GitHub → Actions, and Render → Events (SETUP_GUIDE 8.2) |
| 7.6.6 | Logs never contain passwords or tokens; logs reviewed weekly | Secrets leaking via logs | A09 | code + process | `server/logger.js:3` (weekly review: Phase 9) |
