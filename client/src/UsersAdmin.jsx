import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi } from './api.js';

const EMPTY_FORM = { name: '', email: '', role: 'student', studentNumber: '' };

// Admin: invite form on top, list of all users below with role and status controls
function UsersAdmin({ me }) {
  const { getToken } = useAuth();
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [message, setMessage] = useState(null);

  // Load the user list from the server
  const loadUsers = useCallback(async () => {
    setUsers(await callApi(getToken, '/api/users'));
  }, [getToken]);

  useEffect(() => {
    loadUsers().catch((err) => setMessage({ type: 'danger', text: err.message }));
  }, [loadUsers]);

  // Run one admin action, show the result, then reload the list. Returns true if it worked.
  async function runAction(action, successText) {
    setMessage(null);
    try {
      await action();
      setMessage({ type: 'success', text: successText });
      await loadUsers();
      return true;
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
      return false;
    }
  }

  // Send the invite form to the server (student number only for students)
  async function inviteUser(event) {
    event.preventDefault();
    const body = { name: form.name, email: form.email, role: form.role };
    if (form.role === 'student' && form.studentNumber) {
      body.studentNumber = form.studentNumber;
    }
    const worked = await runAction(() => callApi(getToken, '/api/users', 'POST', body), `Invitation sent to ${form.email}.`);
    if (worked) {
      setForm(EMPTY_FORM);
    }
  }

  // Give a user another role
  function changeRole(user, role) {
    runAction(() => callApi(getToken, `/api/users/${user.id}/role`, 'PATCH', { role }), `${user.name} is now ${role}.`);
  }

  // Disable an account, or enable it again
  function changeStatus(user, status) {
    runAction(() => callApi(getToken, `/api/users/${user.id}/status`, 'PATCH', { status }), `${user.name} is now ${status}.`);
  }

  // Update one field of the invite form as the admin types
  function updateForm(event) {
    setForm({ ...form, [event.target.name]: event.target.value });
  }

  return (
    <div>
      {message && <div className={`alert alert-${message.type}`}>{message.text}</div>}

      <h2 className="h5">Invite a user</h2>
      <form className="row g-2 mb-4" onSubmit={inviteUser}>
        <div className="col-md-3">
          <input className="form-control" name="name" placeholder="Full name" value={form.name} onChange={updateForm} required maxLength={100} />
        </div>
        <div className="col-md-3">
          <input className="form-control" name="email" type="email" placeholder="University email" value={form.email} onChange={updateForm} required maxLength={254} />
        </div>
        <div className="col-md-2">
          <select className="form-select" name="role" value={form.role} onChange={updateForm}>
            <option value="student">Student</option>
            <option value="instructor">Instructor</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div className="col-md-2">
          {form.role === 'student' && (
            <input className="form-control" name="studentNumber" placeholder="Student number" value={form.studentNumber} onChange={updateForm} maxLength={20} />
          )}
        </div>
        <div className="col-md-2">
          <button className="btn btn-primary w-100" type="submit">Send invitation</button>
        </div>
      </form>

      <h2 className="h5">All users</h2>
      <table className="table table-sm align-middle">
        <thead>
          <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Signed up</th><th></th></tr>
        </thead>
        <tbody>
          {/* 🔒 SECURITY 7.1.1 — Names and emails shown as plain text by React, never as HTML (OWASP A03) */}
          {users.map((user) => (
            <tr key={user.id} className={user.status === 'disabled' ? 'text-muted' : ''}>
              <td>{user.name}{user.studentNumber && <small className="text-muted"> ({user.studentNumber})</small>}</td>
              <td>{user.email}</td>
              <td>
                {/* 🔒 SECURITY 7.1.5 — Own row has no controls, for clarity only; the server refuses self-changes too (OWASP A01) */}
                {user.id === me.id ? user.role : (
                  <select className="form-select form-select-sm" value={user.role} onChange={(event) => changeRole(user, event.target.value)}>
                    <option value="student">student</option>
                    <option value="instructor">instructor</option>
                    <option value="admin">admin</option>
                  </select>
                )}
              </td>
              <td>{user.status}</td>
              <td>{user.hasSignedUp ? 'yes' : 'invited'}</td>
              <td>
                {user.id !== me.id && (user.status === 'active'
                  ? <button className="btn btn-sm btn-outline-danger" onClick={() => changeStatus(user, 'disabled')}>Disable</button>
                  : <button className="btn btn-sm btn-outline-success" onClick={() => changeStatus(user, 'active')}>Enable</button>)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default UsersAdmin;
