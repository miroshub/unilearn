// One helper for every call to our API, so each call sends the token the same way.

// Call our API with the user's Clerk token. Returns the JSON answer, or throws an Error with the server's message.
export async function callApi(getToken, path, method = 'GET', body = undefined) {
  // 🔒 SECURITY 7.1.3 — The token comes fresh from Clerk for each call; we never store it (OWASP A07)
  const token = await getToken();
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const answer = await response.json();
  if (!response.ok) {
    const error = new Error(answer.error || 'Something went wrong');
    error.code = answer.code;
    throw error;
  }
  return answer;
}
