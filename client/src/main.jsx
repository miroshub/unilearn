import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ClerkProvider } from '@clerk/react';
// Bootstrap styles, bundled with our code so the CSP can stay 'self' for stylesheets (D27)
import 'bootstrap/dist/css/bootstrap.min.css';
import App from './App.jsx';

// 🔒 SECURITY 7.1.4 — Only the *publishable* Clerk key is in front-end code (OWASP A05)
// It is public by design. The secret key lives only on the server (server/.env, Render settings).
const publishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;

// Start the React app inside the <div id="root"> in index.html, with Clerk around it
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ClerkProvider publishableKey={publishableKey}>
      <App />
    </ClerkProvider>
  </StrictMode>
);
