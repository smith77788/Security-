const BASE = "/api";
const TOKEN_KEY = "fs_token";

export const auth = {
  getToken: () => localStorage.getItem(TOKEN_KEY),
  setToken: (t) => localStorage.setItem(TOKEN_KEY, t),
  clearToken: () => localStorage.removeItem(TOKEN_KEY),
  isLoggedIn: () => !!localStorage.getItem(TOKEN_KEY),
};

async function request(path, options = {}) {
  const token = auth.getToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
    ...options,
  });
  if (res.status === 401 && !path.startsWith("/auth/")) {
    auth.clearToken();
    window.dispatchEvent(new Event("fs:unauthorized"));
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),

  // Auth
  login: (password) => request("/auth/login", { method: "POST", body: JSON.stringify({ password }) }),

  // Locations
  locations: () => request("/locations"),
  locationsSummary: () => request("/locations/summary"),
  createLocation: (body) => request("/locations", { method: "POST", body: JSON.stringify(body) }),
  updateLocation: (id, body) => request(`/locations/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteLocation: (id) => request(`/locations/${id}`, { method: "DELETE" }),
  rotateKey: (id) => request(`/locations/${id}/rotate-key`, { method: "POST" }),

  // Dashboard
  score: (locationId) => request(`/dashboard/score${locationId ? `?location_id=${locationId}` : ""}`),

  // Devices
  devices: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/devices${q ? "?" + q : ""}`);
  },
  updateDevice: (id, body) => request(`/devices/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  acknowledgeDevice: (id) => request(`/devices/${id}/acknowledge`, { method: "POST" }),
  blockDevice: (id, reason) => request(`/devices/${id}/block`, { method: "POST", body: JSON.stringify({ reason }) }),
  unblockDevice: (id) => request(`/devices/${id}/unblock`, { method: "POST" }),
  blockedDevices: () => request("/devices/blocked/list"),
  scanDevices: () => request("/devices/scan", { method: "POST" }),

  // DNS
  topDomains: (period = "24h", locationId) =>
    request(`/dns/top-domains?period=${period}&limit=20${locationId ? `&location_id=${locationId}` : ""}`),
  topDevicesDNS: (period = "24h", locationId) =>
    request(`/dns/top-devices?period=${period}${locationId ? `&location_id=${locationId}` : ""}`),
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
  markAllAlertsRead: (locationId) =>
    request(`/alerts/read-all${locationId ? `?location_id=${locationId}` : ""}`, { method: "POST" }),

  // Assistant
  ask: (question, locationId) =>
    request("/assistant", { method: "POST", body: JSON.stringify({ question, location_id: locationId }) }),

  // Settings
  settings: () => request("/settings"),
  updateSetting: (key, value) => request(`/settings/${key}`, { method: "PUT", body: JSON.stringify({ value }) }),
  clearLogs: () => request("/settings/logs", { method: "DELETE" }),
  applyRetention: () => request("/settings/apply-retention", { method: "POST" }),
  testTelegram: () => request("/settings/test-telegram", { method: "POST" }),

  // Network map & topology
  networkTopology: (queryString = "") => request(`/network/topology${queryString}`),
  connections: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/network/connections${q ? "?" + q : ""}`);
  },
  networkConfig: () => request("/network/config"),
  fingerprints: () => request("/network/fingerprints"),

  // Bandwidth
  bandwidthTimeline: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/network/bandwidth/timeline${q ? "?" + q : ""}`);
  },
  bandwidthTop: (params = {}) => {
    const q = new URLSearchParams(params).toString();
    return request(`/network/bandwidth/top${q ? "?" + q : ""}`);
  },

  // Threat intelligence
  intelStatus: () => request("/intel/status"),
  intelRefresh: () => request("/intel/refresh", { method: "POST" }),
  lookupIp: (ip) => request(`/intel/lookup/ip?ip=${encodeURIComponent(ip)}`),
  lookupDomain: (domain) => request(`/intel/lookup/domain?domain=${encodeURIComponent(domain)}`),
  beaconing: (queryString = "") => request(`/intel/beaconing${queryString}`),
  beaconingAlert: (queryString = "") => request(`/intel/beaconing/alert${queryString}`, { method: "POST" }),
};
