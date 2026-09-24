const baseUrl = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "/api" : "");
const apiKey = import.meta.env.VITE_API_KEY;

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "ngrok-skip-browser-warning": "true",
      ...(apiKey ? { "X-API-Key": apiKey } : {}),
      ...options.headers,
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

export const analyzeEmail = (body) => request("/analyze", { method: "POST", body: JSON.stringify(body) });
export const getInvestigation = (investigationId) => request(`/investigation/${encodeURIComponent(investigationId)}`);
export const getHistory = (userId) => request(`/history?user_id=${encodeURIComponent(userId)}`);
