import { Fragment, useCallback, useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi } from './api.js';
import { MyWork, SubmissionsList } from './Submissions.jsx';

// One course's assignments and exams. Instructors also get a form to add one.
function AssignmentsSection({ course, me }) {
  const { getToken } = useAuth();
  const [assignments, setAssignments] = useState([]);
  const [message, setMessage] = useState(null);
  // Instructor: the assignment whose submissions are opened below its row
  const [openId, setOpenId] = useState(null);
  const address = `/api/courses/${course.id}/assignments`;

  // Load the course's assignments from the server
  const loadAssignments = useCallback(async () => {
    setAssignments(await callApi(getToken, address));
  }, [getToken, address]);

  useEffect(() => {
    loadAssignments().catch((err) => setMessage({ type: 'danger', text: err.message }));
  }, [loadAssignments]);

  // Send the "add" form to the server, then reload the list
  async function createAssignment(event) {
    event.preventDefault();
    const form = event.target;
    const fields = Object.fromEntries(new FormData(form));
    setMessage(null);
    try {
      await callApi(getToken, address, 'POST', {
        title: fields.title,
        type: fields.type,
        // The browser gives local time ("2026-11-30T23:59"); send it as an exact moment in time
        dueAt: new Date(fields.dueAt).toISOString(),
        maxScore: Number(fields.maxScore),
      });
      form.reset();
      setMessage({ type: 'success', text: `"${fields.title}" added.` });
      await loadAssignments();
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
    }
  }

  return (
    <div className="mt-4">
      <h3 className="h6">Assignments and exams</h3>
      {message && <div className={`alert alert-${message.type} py-2`}>{message.text}</div>}

      {/* 🔒 SECURITY 7.1.5 — The form is shown to instructors only, for clarity; the server checks role and course anyway (OWASP A01) */}
      {me.role === 'instructor' && (
        <form className="row g-2 mb-3" onSubmit={createAssignment}>
          <div className="col-md-4">
            <input className="form-control form-control-sm" name="title" placeholder="Title" required maxLength={200} />
          </div>
          <div className="col-md-2">
            <select className="form-select form-select-sm" name="type" defaultValue="assignment">
              <option value="assignment">Assignment</option>
              <option value="exam">Exam</option>
            </select>
          </div>
          <div className="col-md-3">
            <input className="form-control form-control-sm" name="dueAt" type="datetime-local" required title="Deadline (assignment) or date (exam)" />
          </div>
          <div className="col-md-1">
            <input className="form-control form-control-sm" name="maxScore" type="number" min={1} max={1000} placeholder="Max" required />
          </div>
          <div className="col-md-2">
            <button className="btn btn-sm btn-primary w-100" type="submit">Add</button>
          </div>
        </form>
      )}

      {assignments.length === 0 ? <p className="text-muted small">Nothing yet.</p> : (
        <table className="table table-sm">
          <thead>
            <tr><th>Title</th><th>Type</th><th>Due</th><th>Max score</th><th>{me.role === 'student' ? 'My work' : ''}</th></tr>
          </thead>
          <tbody>
            {/* 🔒 SECURITY 7.1.1 — Titles shown as plain text by React, never as HTML (OWASP A03) */}
            {assignments.map((assignment) => (
              <Fragment key={assignment.id}>
                <tr>
                  <td>{assignment.title}</td>
                  <td><span className={`badge ${assignment.type === 'exam' ? 'bg-warning text-dark' : 'bg-info text-dark'}`}>{assignment.type}</span></td>
                  <td>{new Date(assignment.dueAt).toLocaleString()}</td>
                  <td>{assignment.maxScore}</td>
                  <td>
                    {me.role === 'student' && <MyWork courseId={course.id} assignment={assignment} onChange={loadAssignments} />}
                    {me.role === 'instructor' && assignment.type === 'assignment' && (
                      <button className="btn btn-sm btn-outline-secondary" onClick={() => setOpenId(openId === assignment.id ? null : assignment.id)}>
                        {openId === assignment.id ? 'Hide submissions' : 'Submissions'}
                      </button>
                    )}
                  </td>
                </tr>
                {openId === assignment.id && (
                  <tr>
                    <td colSpan={5}><SubmissionsList courseId={course.id} assignment={assignment} /></td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default AssignmentsSection;
