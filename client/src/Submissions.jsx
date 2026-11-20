import { useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi, downloadFile, sha256Of, MAX_PDF_BYTES } from './api.js';
import Fingerprint from './Fingerprint.jsx';

// Student: their own work for one assignment — status, upload/replace before the deadline, download, score
export function MyWork({ courseId, assignment, onChange }) {
  const { getToken } = useAuth();
  const [problem, setProblem] = useState(null);
  const [busy, setBusy] = useState(false);
  // Result of comparing the file's fingerprint in the browser with the server's receipt
  const [receiptCheck, setReceiptCheck] = useState(null);
  const address = `/api/courses/${courseId}/assignments/${assignment.id}/submissions`;
  const mine = assignment.mySubmission;
  // For clarity only: the server checks the deadline with its own clock (D21)
  const isClosed = new Date(assignment.dueAt) < new Date();

  // Upload the chosen PDF (replaces an earlier one), then reload the assignment list
  async function upload(event) {
    const file = event.target.files[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    if (file.size > MAX_PDF_BYTES) {
      setProblem('The file is larger than 10 MB.');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    setProblem(null);
    setReceiptCheck(null);
    setBusy(true);
    try {
      const localSha256 = await sha256Of(file);
      const receipt = await callApi(getToken, `${address}/mine`, 'PUT', formData);
      // 🔒 SECURITY 7.2.9 — The server's SHA-256 must equal the one this browser worked out (OWASP A08)
      setReceiptCheck(receipt.fileSha256 === localSha256 ? 'match' : 'mismatch');
      await onChange();
    } catch (err) {
      setProblem(err.message);
    }
    setBusy(false);
  }

  // Download the student's own PDF
  function download() {
    downloadFile(getToken, `${address}/${mine.id}/file`, `${assignment.title}.pdf`).catch((err) => setProblem(err.message));
  }

  // The student's own score (the server only ever sends their own, 7.2.2)
  const myScore = assignment.myScore !== null && assignment.myScore !== undefined && (
    <strong className="d-block">Score: {assignment.myScore} / {assignment.maxScore}</strong>
  );

  if (assignment.type === 'exam') {
    return myScore || <small className="text-muted">No upload (score entered by instructor)</small>;
  }

  return (
    <div>
      {myScore}
      {mine
        ? <small className="text-success d-block">Submitted {new Date(mine.submittedAt).toLocaleString()}</small>
        : <small className="text-muted d-block">Not submitted</small>}
      {mine && <button className="btn btn-sm btn-link px-0" onClick={download}>Download my PDF</button>}
      {mine && <Fingerprint sha256={mine.fileSha256} />}
      {receiptCheck === 'match' && <small className="text-success d-block">✔ The server received exactly your file (SHA-256 matches).</small>}
      {receiptCheck === 'mismatch' && <small className="text-danger d-block">The server's fingerprint differs from your file. Upload it again.</small>}
      {/* 🔒 SECURITY 7.1.5 — Upload hidden once graded or past the deadline, for clarity; the server refuses anyway (OWASP A01) */}
      {assignment.graded && <small className="d-block">Graded — locked</small>}
      {!assignment.graded && isClosed && <small className="d-block">Deadline passed</small>}
      {!assignment.graded && !isClosed && (
        <label className={`btn btn-sm btn-outline-primary mt-1 ${busy ? 'disabled' : ''}`}>
          {busy ? 'Uploading…' : mine ? 'Replace PDF' : 'Upload PDF'}
          <input type="file" accept="application/pdf,.pdf" hidden onChange={upload} disabled={busy} />
        </label>
      )}
      {problem && <small className="text-danger d-block">{problem}</small>}
    </div>
  );
}
