import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi } from './api.js';
import AssignmentsSection from './AssignmentsSection.jsx';

const EMPTY_FORM = { code: '', title: '', term: '' };

// Admin: create courses, then pick one to assign instructors, enrol students and view grades (read only)
function CoursesAdmin({ me }) {
  const { getToken } = useAuth();
  const [courses, setCourses] = useState([]);
  const [users, setUsers] = useState([]);
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [message, setMessage] = useState(null);

  // Load all courses and all users (the users fill the "add instructor" and "add student" lists)
  const loadAll = useCallback(async () => {
    setCourses(await callApi(getToken, '/api/courses'));
    setUsers(await callApi(getToken, '/api/users'));
  }, [getToken]);

  useEffect(() => {
    loadAll().catch((err) => setMessage({ type: 'danger', text: err.message }));
  }, [loadAll]);

  // Run one admin action; the server answers with the updated course, which becomes the selected one
  async function runAction(action, successText) {
    setMessage(null);
    try {
      const course = await action();
      setSelected(course);
      setMessage({ type: 'success', text: successText });
      setCourses(await callApi(getToken, '/api/courses'));
      return true;
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
      return false;
    }
  }

  // Send the new course form to the server
  async function createCourse(event) {
    event.preventDefault();
    const worked = await runAction(() => callApi(getToken, '/api/courses', 'POST', form), `Course ${form.code} created.`);
    if (worked) {
      setForm(EMPTY_FORM);
    }
  }

  // Open one course with its instructors and students
  async function openCourse(courseId) {
    setMessage(null);
    try {
      setSelected(await callApi(getToken, `/api/courses/${courseId}`));
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
    }
  }

  // Assign an instructor to the selected course
  function addInstructor(instructorId) {
    runAction(() => callApi(getToken, `/api/courses/${selected.id}/instructors`, 'POST', { instructorId }), 'Instructor assigned.');
  }

  // Take an instructor off the selected course
  function removeInstructor(instructor) {
    runAction(() => callApi(getToken, `/api/courses/${selected.id}/instructors/${instructor.id}`, 'DELETE'), `${instructor.name} removed.`);
  }

  // Enrol a student in the selected course
  function addStudent(studentId) {
    runAction(() => callApi(getToken, `/api/courses/${selected.id}/enrollments`, 'POST', { studentId }), 'Student enrolled.');
  }

  // Take a student off the selected course
  function removeStudent(student) {
    runAction(() => callApi(getToken, `/api/courses/${selected.id}/enrollments/${student.id}`, 'DELETE'), `${student.name} unenrolled.`);
  }

  // Update one field of the new course form as the admin types
  function updateForm(event) {
    setForm({ ...form, [event.target.name]: event.target.value });
  }

  // Active users with this role who are not on the selected course yet (choices for the "add" lists)
  function choicesFor(role, alreadyOnCourse) {
    const takenIds = alreadyOnCourse.map((person) => person.id);
    return users.filter((user) => user.role === role && user.status === 'active' && !takenIds.includes(user.id));
  }

  return (
    <div>
      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}

      <h2 className="h5">Create a course</h2>
      <form className="row g-2 mb-4" onSubmit={createCourse}>
        <div className="col-md-2">
          <input className="form-control" name="code" placeholder="Code, e.g. CS101" value={form.code} onChange={updateForm} required maxLength={20} />
        </div>
        <div className="col-md-5">
          <input className="form-control" name="title" placeholder="Title" value={form.title} onChange={updateForm} required maxLength={200} />
        </div>
        <div className="col-md-3">
          <input className="form-control" name="term" placeholder="Term, e.g. 2026-Fall" value={form.term} onChange={updateForm} required maxLength={20} />
        </div>
        <div className="col-md-2">
          <button className="btn btn-primary w-100" type="submit">Create</button>
        </div>
      </form>

      <h2 className="h5">All courses</h2>
      <table className="table table-sm align-middle">
        <thead>
          <tr><th>Code</th><th>Title</th><th>Term</th><th>Instructors</th><th></th></tr>
        </thead>
        <tbody>
          {/* 🔒 SECURITY 7.1.1 — Course and people names shown as plain text by React, never as HTML (OWASP A03) */}
          {courses.map((course) => (
            <tr key={course.id} className={selected?.id === course.id ? 'table-active' : ''}>
              <td>{course.code}</td>
              <td>{course.title}</td>
              <td>{course.term}</td>
              <td>{course.instructors.map((instructor) => instructor.name).join(', ') || '—'}</td>
              <td><button className="btn btn-sm btn-outline-primary" onClick={() => openCourse(course.id)}>Manage</button></td>
            </tr>
          ))}
        </tbody>
      </table>

      {selected && (
        <div className="card">
          <div className="card-body">
            <h3 className="h5">{selected.code} — {selected.title} <small className="text-muted">({selected.term})</small></h3>

            <h4 className="h6 mt-3">Instructors</h4>
            <PeopleList people={selected.instructors} onRemove={removeInstructor} />
            <AddPersonSelect label="Assign an instructor…" choices={choicesFor('instructor', selected.instructors)} onAdd={addInstructor} />

            <h4 className="h6 mt-4">Students</h4>
            <PeopleList people={selected.students} onRemove={removeStudent} />
            <AddPersonSelect label="Enrol a student…" choices={choicesFor('student', selected.students)} onAdd={addStudent} />

            {/* Admins view all grades read-only (proposal §4); "key" reloads the list when another course is opened */}
            <AssignmentsSection key={selected.id} course={selected} me={me} />
          </div>
        </div>
      )}
    </div>
  );
}

// A list of people on a course, each with a "Remove" button
function PeopleList({ people, onRemove }) {
  if (people.length === 0) {
    return <p className="text-muted small">Nobody yet.</p>;
  }
  return (
    <ul className="list-group mb-2">
      {people.map((person) => (
        <li key={person.id} className="list-group-item d-flex justify-content-between align-items-center">
          <span>
            {person.name}
            {person.email && <small className="text-muted"> {person.email}</small>}
            {person.status === 'disabled' && <span className="badge bg-secondary ms-2">disabled</span>}
          </span>
          <button className="btn btn-sm btn-outline-danger" onClick={() => onRemove(person)}>Remove</button>
        </li>
      ))}
    </ul>
  );
}

// A drop-down list: choosing a person adds them straight away
function AddPersonSelect({ label, choices, onAdd }) {
  // Add the chosen person, then put the list back to its label
  function choose(event) {
    if (event.target.value) {
      onAdd(event.target.value);
      event.target.value = '';
    }
  }
  return (
    <select className="form-select form-select-sm" defaultValue="" onChange={choose} disabled={choices.length === 0}>
      <option value="">{choices.length === 0 ? 'Nobody left to add' : label}</option>
      {choices.map((user) => (
        <option key={user.id} value={user.id}>{user.name} ({user.email})</option>
      ))}
    </select>
  );
}

export default CoursesAdmin;
