import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi } from './api.js';
import AssignmentsSection from './AssignmentsSection.jsx';
import MaterialsSection from './MaterialsSection.jsx';

// Instructor and student dashboard: "My courses". The server only sends this user's own courses.
function MyCourses({ me }) {
  const { getToken } = useAuth();
  const [courses, setCourses] = useState(null);
  const [selected, setSelected] = useState(null);
  const [problem, setProblem] = useState(null);

  // Load the user's own courses once when the page opens
  useEffect(() => {
    callApi(getToken, '/api/courses').then(setCourses).catch((err) => setProblem(err.message));
  }, [getToken]);

  // Open one course (the server checks again that it is one of the user's own)
  async function openCourse(courseId) {
    setProblem(null);
    try {
      setSelected(await callApi(getToken, `/api/courses/${courseId}`));
    } catch (err) {
      setProblem(err.message);
    }
  }

  if (problem) {
    return <div className="alert alert-danger">{problem}</div>;
  }
  if (!courses) {
    return <p>Loading…</p>;
  }

  // One course opened: its instructors, and for instructors the class list
  if (selected) {
    return (
      <div>
        <button className="btn btn-link px-0 mb-2" onClick={() => setSelected(null)}>← My courses</button>
        <h2 className="h4">{selected.code} — {selected.title}</h2>
        <p className="text-muted">
          {selected.term} · Taught by {selected.instructors.map((instructor) => instructor.name).join(', ') || '—'}
        </p>
        {/* 🔒 SECURITY 7.1.5 — The class list is shown to instructors only; the server doesn't even send it to students (OWASP A01) */}
        {me.role === 'instructor' && selected.students && (
          <>
            <h3 className="h6">Students ({selected.students.length})</h3>
            <table className="table table-sm">
              <thead>
                <tr><th>Name</th><th>Student number</th><th>Email</th></tr>
              </thead>
              <tbody>
                {selected.students.map((student) => (
                  <tr key={student.id} className={student.status === 'disabled' ? 'text-muted' : ''}>
                    <td>{student.name}</td>
                    <td>{student.studentNumber || '—'}</td>
                    <td>{student.email}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        <AssignmentsSection course={selected} me={me} />
        <MaterialsSection course={selected} me={me} />
      </div>
    );
  }

  return (
    <div>
      <h2 className="h5">My courses</h2>
      {courses.length === 0 && (
        <p className="text-muted">
          {me.role === 'instructor' ? 'You are not teaching any courses yet.' : 'You are not enrolled in any courses yet.'}
        </p>
      )}
      <div className="list-group">
        {/* 🔒 SECURITY 7.1.1 — Course names shown as plain text by React, never as HTML (OWASP A03) */}
        {courses.map((course) => (
          <button key={course.id} className="list-group-item list-group-item-action" onClick={() => openCourse(course.id)}>
            <strong>{course.code}</strong> — {course.title}
            <small className="text-muted ms-2">{course.term}</small>
          </button>
        ))}
      </div>
    </div>
  );
}

export default MyCourses;
