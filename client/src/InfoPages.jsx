// Two public pages anyone can read, signed in or not: the privacy notice (GDPR, D22) and security tips (7.5.6).

// Link back to the start page, shown at the top of both pages
function BackLink() {
  return <a href="/" className="d-inline-block mb-3">← Back to UniLearn</a>;
}

// 🔒 SECURITY 7.3.5 — Privacy notice: what UniLearn stores, why, where, for how long, and your rights (GDPR, D22)
export function PrivacyNotice() {
  return (
    <div className="col-lg-9">
      <BackLink />
      <h1 className="h3">Privacy notice</h1>
      <p className="text-muted">
        UniLearn is a university course project (secure learning management system). This page explains how it handles
        personal data, following the GDPR.
      </p>

      <h2 className="h5 mt-4">What we store, and why</h2>
      <table className="table table-sm">
        <thead><tr><th>Data</th><th>Why we need it</th></tr></thead>
        <tbody>
          <tr><td>Name, university email, role, student number (students)</td><td>To give you an account and show your work to your instructors</td></tr>
          <tr><td>Your courses (enrolments)</td><td>To show you only your own courses</td></tr>
          <tr><td>PDFs you hand in, with their date and SHA-256 fingerprint</td><td>So instructors can grade them and you can prove what you handed in</td></tr>
          <tr><td>Grades</td><td>Your academic record</td></tr>
          <tr><td>Audit log of staff actions (roles, accounts, grades)</td><td>To show who changed what, if anything is ever disputed</td></tr>
          <tr><td>IP address and time of requests, in server logs</td><td>To detect and stop attacks</td></tr>
        </tbody>
      </table>
      <p>
        We store <strong>only what teaching needs</strong>. UniLearn never sees or stores your password: sign-in,
        passwords and two-step verification are handled by Clerk. Students never see other students' details.
      </p>

      <h2 className="h5 mt-4">Who processes it</h2>
      <ul>
        <li><strong>Clerk</strong>: sign-in, passwords and two-step verification (USA-based).</li>
        <li><strong>MongoDB Atlas</strong>: the database. PDFs are encrypted by UniLearn (AES-256) before they are stored.</li>
        <li><strong>Render</strong>: runs the UniLearn server and keeps its logs.</li>
        <li><strong>Cloudflare</strong>: secure connection (HTTPS) and protection against attacks.</li>
      </ul>

      <h2 className="h5 mt-4">How long we keep it</h2>
      <ul>
        <li>Your account: while you study or work here.</li>
        <li>When you leave, an administrator disables and then <strong>anonymises</strong> your account: your name, email,
          student number, sign-in account and PDFs are removed.</li>
        <li>Grades are kept under an anonymous ID, because the university must keep academic records.</li>
        <li>Weekly backups are encrypted and deleted after four weeks.</li>
      </ul>

      <h2 className="h5 mt-4">Your rights</h2>
      <ul>
        <li><strong>See your data:</strong> after signing in, click <em>Download my data</em> at the bottom of your home page.</li>
        <li><strong>Correct it:</strong> ask an administrator to fix a wrong name or email.</li>
        <li><strong>Erase it:</strong> when you leave, ask an administrator to anonymise your account.</li>
        <li>You can also complain to your national data protection authority.</li>
      </ul>

      <h2 className="h5 mt-4">If something goes wrong</h2>
      <p>
        If personal data is ever leaked, the data protection authority is told within <strong>72 hours</strong>, and
        you are told directly if it puts you at high risk.
      </p>
      <p>Questions: contact your UniLearn administrator.</p>
    </div>
  );
}

// 🔒 SECURITY 7.5.6 — One-page security tips for users (phishing, passwords, two-step codes)
export function SecurityTips() {
  return (
    <div className="col-lg-9">
      <BackLink />
      <h1 className="h3">Security tips</h1>
      <p className="text-muted">Eight habits that keep your UniLearn account safe.</p>
      <ol className="lh-lg">
        <li><strong>Check the address</strong> before you sign in: it must start with <code>https://</code> and show the padlock.
          A look-alike page can steal your password.</li>
        <li><strong>Nobody from UniLearn will ever ask for your password or code</strong>, by email, chat or phone.
          Anyone who asks is an attacker.</li>
        <li><strong>Never share a two-step verification code.</strong> It only proves it's you while nobody else knows it.</li>
        <li><strong>Use a long password you don't use anywhere else</strong> (a password manager helps). UniLearn refuses
          passwords that have appeared in known data leaks.</li>
        <li><strong>Turn on two-step verification</strong> (an authenticator app). It is required for staff, and a good idea for everyone.</li>
        <li><strong>Sign out on shared computers</strong> (menu at the top right).</li>
        <li><strong>Check your receipt after handing in</strong>: the green ✔ means the server got exactly your file, and
          "Verify signature" proves the receipt really came from UniLearn.</li>
        <li><strong>Report anything strange</strong> to an administrator: a grade with a ⚠ warning, a sign-in email you
          didn't expect, or a message that pushes you to act fast.</li>
      </ol>
    </div>
  );
}

// Small links to both pages, shown under the sign-in box and at the bottom of the home page
export function InfoLinks() {
  return (
    <p className="text-center small mt-4">
      <a href="/privacy">Privacy notice</a> · <a href="/security-tips">Security tips</a>
    </p>
  );
}
