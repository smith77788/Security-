const BASE = "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),

  // Dashboard
  score: () => request("/dashboard/score"),

  // Devices
  devices: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/devices${q ? "?" + q : ""}`);
  },
  updateDevice: (id, body) => request(`/devices/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  acknowledgeDevice: (id) => request(`/devices/${id}/acknowledge`, { method: "POST" }),

  // DNS
  topDomains: (period = "24h") => request(`/dns/top-domains?period=${period}&limit=20`),
  topDevicesDNS: (period = "24h") => request(`/dns/top-devices?period=${period}`),
  recentQueries: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/dns/recent${q ? "?" + q : ""}`);
  },

  // Alerts
  alerts: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/alerts${q ? "?" + q : ""}`);
  },
  markAlertRead: (id) => request(`/alerts/${id}/read`, { method: "POST" }),
  markAllAlertsRead: () => request("/alerts/read-all", { method: "POST" }),

  // Assistant
  ask: (question) => request("/assistant", { method: "POST", body: JSON.stringify({ question }) }),

  // Settings
  settings: () => request("/settings"),
  updateSetting: (key, value) => request(`/settings/${key}`, { method: "PUT", body: JSON.stringify({ value }) }),
  clearLogs: () => request("/settings/logs", { method: "DELETE" }),
  applyRetention: () => request("/settings/apply-retention", { method: "POST" }),
};
