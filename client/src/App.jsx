import { Show, SignIn, SignUp } from '@clerk/react';
import HomePage from './HomePage.jsx';

// True when the visitor arrived by clicking the link in an invitation email
const cameFromInvitation = new URLSearchParams(window.location.search).has('__clerk_ticket');

// Main page: the sign-in box for visitors, the home page for signed-in users
function App() {
  return (
    <div className="container py-5">
      <Show when="signed-out">
        <h1 className="text-center mb-4">UniLearn</h1>
        <div className="d-flex justify-content-center">
          {/* There is no public sign-up. The sign-up box only appears for invited people (7.5.4). */}
          {cameFromInvitation ? <SignUp routing="hash" /> : <SignIn routing="hash" />}
        </div>
      </Show>
      <Show when="signed-in">
        <HomePage />
      </Show>
    </div>
  );
}

export default App;
