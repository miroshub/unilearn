import { useState } from 'react';
import UsersAdmin from './UsersAdmin.jsx';
import AuditLog from './AuditLog.jsx';
import CoursesAdmin from './CoursesAdmin.jsx';

// The admin tabs: their key and the text on the tab
const TABS = [
  { key: 'users', label: 'Users' },
  { key: 'courses', label: 'Courses' },
  { key: 'audit', label: 'Audit log' },
];

// Admin dashboard: three tabs, "Users", "Courses" and "Audit log"
function AdminPage({ me }) {
  const [tab, setTab] = useState('users');

  return (
    <div>
      <ul className="nav nav-tabs mb-3">
        {TABS.map(({ key, label }) => (
          <li key={key} className="nav-item">
            <button className={`nav-link ${tab === key ? 'active' : ''}`} onClick={() => setTab(key)}>{label}</button>
          </li>
        ))}
      </ul>
      {tab === 'users' && <UsersAdmin me={me} />}
      {tab === 'courses' && <CoursesAdmin />}
      {tab === 'audit' && <AuditLog />}
    </div>
  );
}

export default AdminPage;
