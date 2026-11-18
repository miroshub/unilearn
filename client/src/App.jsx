import { Show, SignIn, SignUp, SignOutButton, useUser } from '@clerk/react';
import HomePage from './HomePage.jsx';

// True when the visitor arrived by clicking the link in an invitation email
const cameFromInvitation = new URLSearchParams(window.location.search).has('__clerk_ticket');

// Someone is already signed in (e.g. the admin) and opened an invitation link in the same browser.
// Signing out comes back to this same link, so the invitation's sign-up box appears.
function InvitationWhileSignedIn() {
  const { user } = useUser();
  return (
    <div className="alert alert-warning">
      <p>
        This is an invitation link, but you are signed in as{' '}
        <strong>{user?.primaryEmailAddress?.emailAddress}</strong>.
        Sign out to accept the invitation, or open the link in a private window.
      </p>
      <SignOutButton redirectUrl={window.location.href}>
        <button className="btn btn-warning">Sign out and accept the invitation</button>
      </SignOutButton>
    </div>
  );
}

// Main page: the sign-in box for visitors, the home page for signed-in users
function App() {
  return (
    <div className="container py-5">
      <Show when="signed-out">
        <h1 className="text-center mb-4">UniLearn</h1>
        <div className="d-flex justify-content-center">
          {/* There is no public sign-up. The sign-up box only appears for invited people (7.5.4). */}
          {/* After sign-up, go to "/" (without the invitation code), so the new user lands on their home page */}
          {cameFromInvitation ? <SignUp routing="hash" forceRedirectUrl="/" /> : <SignIn routing="hash" />}
        </div>
      </Show>
      <Show when="signed-in">
        {cameFromInvitation ? <InvitationWhileSignedIn /> : <HomePage />}
      </Show>
    </div>
  );
}

export default App;
