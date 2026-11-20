import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi, downloadFile } from './api.js';
import Fingerprint from './Fingerprint.jsx';

// Grade book for one assignment or exam: every enrolled student, their work and their score.
// Instructors can download work and enter scores; admins only read (the server refuses their changes anyway).
function GradeBook({ courseId, assignment, me }) {
  const { getToken } = useAuth();
  const [rows, setRows] = useState(null);
  const [message, setMessage] = useState(null);
  const address = `/api/courses/${courseId}/assignments/${assignment.id}/grades`;
  const canGrade = me.role === 'instructor';

  // Load the grade book from the server
  const loadRows = useCallback(async () => {
    setRows(await callApi(getToken, address));
  }, [getToken, address]);

  useEffect(() => {
    loadRows().catch((err) => setMessage({ type: 'danger', text: err.message }));
  }, [loadRows]);

  // Save one student's score, then reload so the table shows what the server stored
  async function saveScore(event, row) {
    event.preventDefault();
    const score = Number(new FormData(event.target).get('score'));
    setMessage(null);
    try {
      await callApi(getToken, `${address}/${row.studentId}`, 'PUT', { score });
      setMessage({ type: 'success', text: `Saved ${score} for ${row.studentName}.` });
      await loadRows();
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
    }
  }

  // Download one student's PDF (instructor only; the server checks again)
  function download(row) {
    const submissionsAddress = `/api/courses/${courseId}/assignments/${assignment.id}/submissions`;
    downloadFile(getToken, `${submissionsAddress}/${row.submissionId}/file`, `${assignment.title} - ${row.studentName}.pdf`)
      .catch((err) => setMessage({ type: 'danger', text: err.message }));
  }

  if (!rows) {
    return message ? <div className="text-danger small">{message.text}</div> : <div className="small">Loading…</div>;
  }

  return (
    <div>
      {message && <div className={`alert alert-${message.type} py-1 small`}>{message.text}</div>}
      {/* 🔒 SECURITY 7.1.5 — Admins get a read-only table, for clarity; the server refuses an admin's grade change anyway (OWASP A01) */}
      {!canGrade && <div className="text-muted small mb-1">Read only: grades are given by the course's instructor.</div>}
      {rows.length === 0 ? <div className="text-muted small">No students enrolled.</div> : (
        <table className="table table-sm mb-0">
          <thead>
            <tr><th>Student</th>{assignment.type === 'assignment' && <th>Submitted</th>}<th>Score (out of {assignment.maxScore})</th></tr>
          </thead>
          <tbody>
            {/* 🔒 SECURITY 7.1.1 — Names shown as plain text by React, never as HTML (OWASP A03) */}
            {rows.map((row) => (
              <tr key={row.studentId}>
                <td>
                  {row.studentName}
                  {row.studentNumber && <small className="text-muted"> ({row.studentNumber})</small>}
                </td>
                {assignment.type === 'assignment' && (
                  <td>
                    {row.submittedAt ? <small>{new Date(row.submittedAt).toLocaleString()}</small> : <small className="text-muted">Not submitted</small>}
                    {row.submissionId && (
                      <>
                        <button className="btn btn-sm btn-link py-0" onClick={() => download(row)}>Download</button>
                        <Fingerprint sha256={row.fileSha256} />
                      </>
                    )}
                  </td>
                )}
                <td>
                  {canGrade && (assignment.type === 'exam' || row.submittedAt) ? (
                    <form className="d-flex gap-1" onSubmit={(event) => saveScore(event, row)}>
                      <input className="form-control form-control-sm" style={{ width: '6rem' }} name="score" type="number"
                        min={0} max={assignment.maxScore} step="any" defaultValue={row.score ?? ''} required />
                      <button className="btn btn-sm btn-outline-primary" type="submit">Save</button>
                    </form>
                  ) : (
                    <span>{row.score ?? '—'}</span>
                  )}
                  {/* The server re-checks UniLearn's digital signature on every grade it shows (7.3.8) */}
                  {row.signatureValid === true && <small className="text-success">✔ signed</small>}
                  {row.signatureValid === false && <small className="text-danger">⚠ signature invalid: changed outside UniLearn</small>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default GradeBook;
