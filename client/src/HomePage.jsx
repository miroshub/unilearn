import { useEffect, useState } from 'react';
import { useAuth, UserButton, UserProfile, SignOutButton } from '@clerk/react';

// Signed-in page: asks our server who the user is, then shows their role or why they are blocked
function HomePage() {
  const { getToken } = useAuth();
  const [me, setMe] = useState(null);
  const [problem, setProblem] = useState(null);

  // Ask the server once when the page opens
  useEffect(() => {
    // Call GET /api/me with the user's Clerk session token
    async function loadMe() {
      // 🔒 SECURITY 7.1.3 — The token comes fresh from Clerk for each call; we never store it (OWASP A07)
      const token = await getToken();
      const response = await fetch('/api/me', { headers: { Authorization: `Bearer ${token}` } });
      const body = await response.json();
      if (response.ok) {
        setMe(body);
      } else {
        setProblem(body);
      }
    }
    loadMe().catch(() => setProblem({ error: 'Could not reach the server. Try again later.' }));
  }, [getToken]);

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
      <h1>Hello, {me.role}</h1>
      <p className="text-muted">Signed in as {me.name}</p>
    </div>
  );
}

export default HomePage;
