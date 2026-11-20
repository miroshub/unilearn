// One helper for every call to our API, so each call sends the token the same way.

// Largest PDF the server accepts (checked in the browser for clarity only; the server checks itself, 7.2.6)
export const MAX_PDF_BYTES = 10 * 1024 * 1024;

// Turn a refused answer into an Error with the server's message (and its code, e.g. "MFA_REQUIRED")
async function toError(response) {
  const answer = await response.json().catch(() => ({}));
  const error = new Error(answer.error || 'Something went wrong');
  error.code = answer.code;
  return error;
}

// Call our API with the user's Clerk token. Returns the JSON answer, or throws an Error with the server's message.
// "body" can be a plain object (sent as JSON) or a FormData (a form with a file, sent as an upload).
export async function callApi(getToken, path, method = 'GET', body = undefined) {
  // 🔒 SECURITY 7.1.3 — The token comes fresh from Clerk for each call; we never store it (OWASP A07)
  const token = await getToken();
  const headers = { Authorization: `Bearer ${token}` };
  const isForm = body instanceof FormData;
  // For a FormData the browser sets the Content-Type itself (it includes the form's boundary)
  if (body !== undefined && !isForm) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined || isForm ? body : JSON.stringify(body),
  });
  if (!response.ok) {
    throw await toError(response);
  }
  return response.json();
}

// SHA-256 fingerprint of a file chosen in the browser, as 64 hex characters (the browser's built-in Web Crypto).
// Compared with the server's receipt after an upload, it proves the server stored exactly this file.
export async function sha256Of(file) {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// Turn base64 text into bytes, the form Web Crypto works with
function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

// 🔒 SECURITY 7.3.8 — The BROWSER checks UniLearn's RSA-PSS signature with the public key from its certificate (OWASP A08)
// True only if "text" is exactly what UniLearn's private key signed. Change one character and it's false.
export async function verifySignature(publicKeySpki, signature, text) {
  if (!signature) {
    return false;
  }
  const publicKey = await crypto.subtle.importKey('spki', base64ToBytes(publicKeySpki),
    { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, publicKey, base64ToBytes(signature),
    new TextEncoder().encode(text));
}

// Download a file from our API (with the token) and save it under the given name
export async function downloadFile(getToken, path, fileName) {
  const token = await getToken();
  const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) {
    throw await toError(response);
  }
  // Put the bytes in a temporary in-browser link and "click" it, so the browser saves the file
  const fileUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = fileUrl;
  link.download = fileName;
  link.click();
  // Free the memory a moment later, once the download has started
  setTimeout(() => URL.revokeObjectURL(fileUrl), 1000);
}
