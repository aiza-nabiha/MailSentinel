export const baseUrl = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "/api" : "");
const apiKey = import.meta.env.VITE_API_KEY;

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    // Carries the Flask session cookie (set at /auth/google/callback
    // or /auth/addon-session) on every request -- without this every
    // call is anonymous and login_required endpoints 401.
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "ngrok-skip-browser-warning": "true",
      ...(apiKey ? { "X-API-Key": apiKey } : {}),
      ...options.headers,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(payload.error || `Request failed (${response.status})`);
    err.status = response.status;
    throw err;
  }
  return payload;
}

// user_id is never sent by the client anymore -- the backend derives
// it from the signed-in session, so every call below is implicitly
// scoped to whoever is logged in.
export const analyzeEmail = (body) => request("/analyze", { method: "POST", body: JSON.stringify(body) });
export const getInvestigation = (investigationId) => request(`/investigation/${encodeURIComponent(investigationId)}?full=true`);
export const getHistory = () => request("/history");
export const getCurrentUser = () => request("/auth/me");
export const logoutUrl = () => `${baseUrl}/auth/logout`;
