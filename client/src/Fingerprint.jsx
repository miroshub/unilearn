// Shows a file's SHA-256 fingerprint: the first 12 characters, and the full value when clicked (to copy and compare).
// 🔒 SECURITY 7.2.9 — The fingerprint lets anyone check that a file is exactly the one that was uploaded (OWASP A08)
function Fingerprint({ sha256 }) {
  if (!sha256) {
    return null;
  }
  return (
    <details className="small text-muted">
      <summary>SHA-256 <code>{sha256.slice(0, 12)}…</code></summary>
      <code className="user-select-all text-break">{sha256}</code>
    </details>
  );
}

export default Fingerprint;
