import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi } from './api.js';

// Show a before/after value as short text, e.g. {"role":"student"} → role: student
function describe(value) {
  if (value === null || value === undefined) {
    return '—';
  }
  return Object.entries(value).map(([name, field]) => `${name}: ${field}`).join(', ');
}

// Admin: read-only table of the newest audit log entries
function AuditLog() {
  const { getToken } = useAuth();
  const [entries, setEntries] = useState([]);
  const [problem, setProblem] = useState(null);

  // Load the entries once when the tab opens
  useEffect(() => {
    callApi(getToken, '/api/audit-logs').then(setEntries).catch((err) => setProblem(err.message));
  }, [getToken]);

  if (problem) {
    return <div className="alert alert-danger">{problem}</div>;
  }

  return (
    <table className="table table-sm">
      <thead>
        <tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Before</th><th>After</th></tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr key={entry.id}>
            <td>{new Date(entry.at).toLocaleString()}</td>
            <td>{entry.actor}</td>
            <td><code>{entry.action}</code></td>
            <td>{entry.target}</td>
            <td>{describe(entry.before)}</td>
            <td>{describe(entry.after)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default AuditLog;
