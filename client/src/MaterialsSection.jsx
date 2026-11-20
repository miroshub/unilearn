import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@clerk/react';
import { callApi, downloadFile, MAX_PDF_BYTES } from './api.js';
import Fingerprint from './Fingerprint.jsx';

// One course's material PDFs: everyone on the course can download; the instructor can upload.
function MaterialsSection({ course, me }) {
  const { getToken } = useAuth();
  const [materials, setMaterials] = useState([]);
  const [message, setMessage] = useState(null);
  const address = `/api/courses/${course.id}/materials`;

  // Load the list of material from the server
  const loadMaterials = useCallback(async () => {
    setMaterials(await callApi(getToken, address));
  }, [getToken, address]);

  useEffect(() => {
    loadMaterials().catch((err) => setMessage({ type: 'danger', text: err.message }));
  }, [loadMaterials]);

  // Send the upload form (title + PDF) to the server, then reload the list
  async function uploadMaterial(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    // Quick check for clarity only; the server checks size and PDF content itself (7.2.6)
    if (formData.get('file').size > MAX_PDF_BYTES) {
      setMessage({ type: 'danger', text: 'The file is larger than 10 MB.' });
      return;
    }
    setMessage(null);
    try {
      await callApi(getToken, address, 'POST', formData);
      form.reset();
      setMessage({ type: 'success', text: `"${formData.get('title')}" uploaded.` });
      await loadMaterials();
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
    }
  }

  // Download one PDF (the server checks again that this course is the user's own)
  async function download(material) {
    setMessage(null);
    try {
      await downloadFile(getToken, `${address}/${material.id}/file`, `${material.title}.pdf`);
    } catch (err) {
      setMessage({ type: 'danger', text: err.message });
    }
  }

  return (
    <div className="mt-4">
      <h3 className="h6">Course material</h3>
      {message && <div className={`alert alert-${message.type} py-2`}>{message.text}</div>}

      {/* 🔒 SECURITY 7.1.5 — Upload form for instructors only, for clarity; the server checks role, course and file anyway (OWASP A01) */}
      {me.role === 'instructor' && (
        <form className="row g-2 mb-3" onSubmit={uploadMaterial}>
          <div className="col-md-5">
            <input className="form-control form-control-sm" name="title" placeholder="Title, e.g. Week 1 slides" required maxLength={200} />
          </div>
          <div className="col-md-5">
            <input className="form-control form-control-sm" name="file" type="file" accept="application/pdf,.pdf" required />
          </div>
          <div className="col-md-2">
            <button className="btn btn-sm btn-primary w-100" type="submit">Upload PDF</button>
          </div>
          <div className="form-text">PDF only, max 10 MB.</div>
        </form>
      )}

      {materials.length === 0 ? <p className="text-muted small">Nothing yet.</p> : (
        <ul className="list-group">
          {/* 🔒 SECURITY 7.1.1 — Titles shown as plain text by React, never as HTML (OWASP A03) */}
          {materials.map((material) => (
            <li key={material.id} className="list-group-item d-flex justify-content-between align-items-center">
              <span>
                {material.title}
                <small className="text-muted ms-2">{new Date(material.uploadedAt).toLocaleDateString()}</small>
                <Fingerprint sha256={material.fileSha256} />
              </span>
              <button className="btn btn-sm btn-outline-primary" onClick={() => download(material)}>Download</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default MaterialsSection;
