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
| 7.1.1 | User text shown only through React's normal output; no raw HTML | XSS | A03 Output Encoding | code | |
| 7.1.2 | HTTPS on every page (Render + Cloudflare) | Eavesdropping, session theft | A02 Communication Security | config | |
| 7.1.3 | Sessions handled by Clerk; tokens never in localStorage | Session theft | A07 Session Management | code | |
| 7.1.4 | No secret keys in front-end code (only the publishable key) | Leaked keys | A05 System Configuration | code | |
| 7.1.5 | Buttons hidden by role for clarity only; the server still checks | Users trying hidden features | A01 Access Control | code | |
| **7.2 Back end** | | | | | |
| 7.2.1 | Sign-in check on every route | Anonymous access | A07 Authentication | code | |
| 7.2.2 | Role + ownership check on every route | Changing grades, seeing others' data | A01 Access Control | code | |
| 7.2.3 | Request data checked against a schema; unknown fields rejected | Malicious input, self-assigned roles | A03 Input Validation | code | |
| 7.2.4 | Limit on requests per minute | Flooding, password guessing | A04, A07 | code | |
| 7.2.5 | Security headers; API accepts calls only from the UniLearn website | Clickjacking, cross-site calls | A05 System Configuration | code | |
| 7.2.6 | Uploads: PDF only, max 10 MB | Harmful files | A04 File Management | code | |
| 7.2.7 | Generic error message to users; details go to the logs | Leaking internals | A05 Error Handling | code | |
| 7.2.8 | Secrets in Render settings; `.env` never in GitHub | Leaked keys | A02, A05 | code + config | `.gitignore:4`, `server/.env.example`; GitHub push protection (SETUP_GUIDE 3.3) |
| **7.3 Database** | | | | | |
| 7.3.1 | Atlas IP access list allows only Render's outbound IPs | Direct DB attacks | A05 Database Security | config | |
| 7.3.2 | App DB user: readWrite on the UniLearn DB only, long generated password | Full takeover if the password leaks | A01, A07 | config | |
| 7.3.3 | Encryption in transit (TLS) and at rest (Atlas default) | Data read in transit or from disk | A02 Data Protection | config | |
| 7.3.4 | Query filters cleaned; data shapes fixed by Mongoose schemas | NoSQL injection | A03 Database Security | code | |
| 7.3.5 | Only data needed for teaching is stored | Size of any breach | A02 Data Protection | code | |
| 7.3.6 | Weekly database backup | Data loss | Recovery | process | |
| **7.4 Network and hosting** | | | | | |
| 7.4.1 | All traffic through the Cloudflare WAF; Always Use HTTPS | DDoS, bots, web attacks | — | config | |
| 7.4.2 | Database accepts connections only from Render (see 7.3.1) | Direct DB attacks | — | config | |
| 7.4.3 | Render manages OS updates, server firewall, physical security (shared responsibility) | Unpatched or exposed servers | — | config | |
| 7.4.4 | 2FA on the GitHub, Render, Atlas, Clerk and Cloudflare accounts | Takeover of control accounts | — | process | |
| 7.4.5 | Dependabot + `npm audit` on every push | Vulnerable packages | A06 | config | `.github/workflows/security-audit.yml`, `.github/dependabot.yml` |
| 7.4.6 | Render deploys only from `main` | Unfinished code going live | — | config | |
| **7.5 Users** | | | | | |
| 7.5.1 | MFA required for admins and instructors | Phishing / account takeover | A07 | code + config | |
| 7.5.2 | Minimum password length; breached passwords rejected | Weak or reused passwords | A07 | config | |
| 7.5.3 | Automatic blocking after repeated failed sign-ins | Password guessing | A07 | config | |
| 7.5.4 | No public sign-up; admins invite by university email | Fake accounts | A07 | code + config | |
| 7.5.5 | Accounts disabled when people leave | Former users keeping access | A01 | code | |
| 7.5.6 | One-page security tips guide for users | Phishing, sharing codes | — | process | |
| **7.6 Logging** | | | | | |
| 7.6.1 | Audit log: grade changes (old + new), role changes, account creation/removal | Untraceable changes (repudiation) | A09 | code | |
| 7.6.2 | Application log: denied access, errors, blocked requests (Render logs) | Unnoticed attacks | A09 | code | |
| 7.6.3 | Sign-in log: sign-ins, failures, MFA events (Clerk dashboard) | Unnoticed account attacks | A09 | config | |
| 7.6.4 | Attack log: blocked requests, bot traffic (Cloudflare) | Unnoticed attacks | A09 | config | |
| 7.6.5 | Deployment log: pushes, checks, deploys (GitHub + Render) | Untraceable releases | A09 | config | |
| 7.6.6 | Logs never contain passwords or tokens; logs reviewed weekly | Secrets leaking via logs | A09 | code + process | |
