import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi, downloadFile, MAX_PDF_BYTES } from './api.js';

// Student: their own work for one assignment — status, upload/replace before the deadline, download
export function MyWork({ courseId, assignment, onChange }) {
  const { getToken } = useAuth();
  const [problem, setProblem] = useState(null);
  const [busy, setBusy] = useState(false);
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
    setBusy(true);
    try {
      await callApi(getToken, `${address}/mine`, 'PUT', formData);
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

  if (assignment.type === 'exam') {
    return <small className="text-muted">No upload (score entered by instructor)</small>;
  }

  return (
    <div>
      {mine
        ? <small className="text-success d-block">Submitted {new Date(mine.submittedAt).toLocaleString()}</small>
        : <small className="text-muted d-block">Not submitted</small>}
      {mine && <button className="btn btn-sm btn-link px-0" onClick={download}>Download my PDF</button>}
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

// Instructor: everyone's submissions for one assignment, each with a download button
export function SubmissionsList({ courseId, assignment }) {
  const { getToken } = useAuth();
  const [submissions, setSubmissions] = useState(null);
  const [problem, setProblem] = useState(null);
  const address = `/api/courses/${courseId}/assignments/${assignment.id}/submissions`;

  // Load the list once when it is opened
  useEffect(() => {
    callApi(getToken, address).then(setSubmissions).catch((err) => setProblem(err.message));
  }, [getToken, address]);

  // Download one student's PDF, named after the student
  function download(submission) {
    downloadFile(getToken, `${address}/${submission.id}/file`, `${assignment.title} - ${submission.studentName}.pdf`)
      .catch((err) => setProblem(err.message));
  }

  if (problem) {
    return <div className="text-danger small">{problem}</div>;
  }
  if (!submissions) {
    return <div className="small">Loading…</div>;
  }
  if (submissions.length === 0) {
    return <div className="text-muted small">No submissions yet.</div>;
  }
  return (
    <ul className="list-group list-group-flush">
      {/* 🔒 SECURITY 7.1.1 — Student names shown as plain text by React, never as HTML (OWASP A03) */}
      {submissions.map((submission) => (
        <li key={submission.id} className="list-group-item d-flex justify-content-between align-items-center px-0">
          <span>
            {submission.studentName}
            {submission.studentNumber && <small className="text-muted"> ({submission.studentNumber})</small>}
            <small className="text-muted ms-2">{new Date(submission.submittedAt).toLocaleString()}</small>
          </span>
          <button className="btn btn-sm btn-outline-primary" onClick={() => download(submission)}>Download</button>
        </li>
      ))}
    </ul>
  );
}
