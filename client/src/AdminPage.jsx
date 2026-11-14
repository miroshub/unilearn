import { useState } from 'react';
import UsersAdmin from './UsersAdmin.jsx';
import AuditLog from './AuditLog.jsx';

// Admin dashboard: two tabs, "Users" and "Audit log"
function AdminPage({ me }) {
  const [tab, setTab] = useState('users');

  return (
    <div>
      <ul className="nav nav-tabs mb-3">
        <li className="nav-item">
          <button className={`nav-link ${tab === 'users' ? 'active' : ''}`} onClick={() => setTab('users')}>Users</button>
        </li>
        <li className="nav-item">
          <button className={`nav-link ${tab === 'audit' ? 'active' : ''}`} onClick={() => setTab('audit')}>Audit log</button>
        </li>
      </ul>
      {tab === 'users' ? <UsersAdmin me={me} /> : <AuditLog />}
    </div>
  );
}

export default AdminPage;
