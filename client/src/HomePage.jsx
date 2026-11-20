import { useEffect, useState } from 'react';
import { useAuth, UserButton, UserProfile, SignOutButton } from '@clerk/react';
import { callApi, downloadMyData } from './api.js';
import { InfoLinks } from './InfoPages.jsx';
import AdminPage from './AdminPage.jsx';
import MyCourses from './MyCourses.jsx';

// Signed-in page: asks our server who the user is, then shows their role or why they are blocked
function HomePage() {
  const { getToken } = useAuth();
  const [me, setMe] = useState(null);
  const [problem, setProblem] = useState(null);
  const [dataProblem, setDataProblem] = useState(null);

  // Ask the server once when the page opens
  useEffect(() => {
    // Call GET /api/me (api.js adds the Clerk session token); a refusal keeps the server's message and code
    callApi(getToken, '/api/me')
      .then(setMe)
      .catch((err) => setProblem({ error: err.message, code: err.code }));
  }, [getToken]);

  // GDPR right of access: save everything UniLearn holds about this user as a JSON file
  function saveMyData() {
    setDataProblem(null);
    downloadMyData(getToken).catch((err) => setDataProblem(err.message));
  }

  // Staff without two-step verification: explain and show Clerk's account page to turn it on
  if (problem?.code === 'MFA_REQUIRED') {
    return (
      <div>
        <div className="alert alert-warning">
          <strong>Two-step verification required.</strong> Admin and instructor accounts must use an
          authenticator app. Below, go to <em>Security</em> → add two-step verification, then sign out
          and sign in again.
        </div>
        <UserProfile routing="hash" />
        <div className="mt-3"><SignOutButton><button className="btn btn-outline-secondary">Sign out</button></SignOutButton></div>
      </div>
    );
  }

  // Any other refusal (no account, account disabled, server down)
  if (problem) {
    return (
      <div>
        <div className="alert alert-danger">{problem.error}</div>
        <SignOutButton><button className="btn btn-outline-secondary">Sign out</button></SignOutButton>
      </div>
    );
  }

  if (!me) {
    return <p>Loading…</p>;
  }

  // 🔒 SECURITY 7.1.1 — Names are shown as plain text by React, never as HTML (OWASP A03)
  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <span className="fs-4 fw-bold">UniLearn</span>
        <UserButton />
      </div>
      <h1 className="h3">Hello, {me.role}</h1>
      <p className="text-muted">Signed in as {me.name}</p>
      {/* 🔒 SECURITY 7.1.5 — Each role sees its own dashboard, for clarity; the server checks the role on every call (OWASP A01) */}
      {me.role === 'admin' ? <AdminPage me={me} /> : <MyCourses me={me} />}
      <hr className="mt-5" />
      <div className="text-center">
        <button className="btn btn-sm btn-outline-secondary" onClick={saveMyData}>Download my data</button>
        {dataProblem && <small className="text-danger d-block">{dataProblem}</small>}
      </div>
      <InfoLinks />
    </div>
  );
}

export default HomePage;
