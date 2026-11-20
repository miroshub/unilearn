import { useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi, verifySignature } from './api.js';

// A student's signed submission receipt: the signed text, and a button that checks the signature
// in THIS browser with the public key from UniLearn's certificate (DECISIONS D40).
function SignedReceipt({ receipt, fileSha256 }) {
  const { getToken } = useAuth();
  const [result, setResult] = useState(null);

  // Fetch UniLearn's certificate, then verify the signature here, without trusting the server's own answer
  async function verify() {
    setResult(null);
    try {
      const pki = await callApi(getToken, '/api/pki');
      const valid = await verifySignature(pki.publicKeySpki, receipt.signature, receipt.text);
      // The signed text must also name the same file fingerprint the page shows
      const sameFile = receipt.text.includes(`file SHA-256: ${fileSha256}`);
      setResult({ valid: valid && sameFile, certificate: pki.signingCertificate, root: pki.rootCertificate });
    } catch (err) {
      setResult({ valid: false, error: err.message });
    }
  }

  if (!receipt) {
    return null;
  }

  return (
    <details className="small">
      <summary>Signed receipt</summary>
      {/* 🔒 SECURITY 7.1.1 — The receipt is shown as plain text by React, never as HTML (OWASP A03) */}
      <pre className="bg-light border rounded p-2 mb-1 text-wrap">{receipt.text}</pre>
      <button className="btn btn-sm btn-outline-secondary" onClick={verify}>Verify signature</button>
      {result?.valid && (
        <div className="text-success mt-1">
          ✔ Valid RSA signature by <strong>{result.certificate.subject.replaceAll('\n', ', ')}</strong>,
          certificate issued by {result.certificate.issuer.replaceAll('\n', ', ')}, valid until {result.certificate.validTo}.
          <div className="text-muted">Root CA SHA-256: <code className="text-break">{result.root.fingerprintSha256}</code></div>
        </div>
      )}
      {result && !result.valid && (
        <div className="text-danger mt-1">✘ The signature does not match this receipt{result.error ? ` (${result.error})` : ''}.</div>
      )}
    </details>
  );
}

export default SignedReceipt;
