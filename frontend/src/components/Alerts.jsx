import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const SEV = {
  critical: { bg: "#7f1d1d", fg: "#fca5a5", border: "#991b1b" },
  warning:  { bg: "#78350f", fg: "#fde68a", border: "#92400e" },
  info:     { bg: "#1e3a5f", fg: "#93c5fd", border: "#1e40af" },
};

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#f1f5f9" },
  toolbar: { display: "flex", gap: 10, marginBottom: 20, alignItems: "center", flexWrap: "wrap" },
  btn: (a) => ({ padding: "6px 14px", borderRadius: 6, border: "1px solid #1e2535", background: a ? "#1d4ed8" : "#161b27", color: a ? "#fff" : "#94a3b8", cursor: "pointer", fontSize: 13 }),
  card: (sev, read) => ({
    borderRadius: 10, padding: "14px 18px", marginBottom: 10,
    display: "flex", alignItems: "flex-start", gap: 12,
    background: SEV[sev]?.bg || "#1e2535",
    border: `1px solid ${SEV[sev]?.border || "#1e2535"}`,
    opacity: read ? 0.55 : 1,
  }),
  badge: (sev) => ({ padding: "3px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, background: SEV[sev]?.bg, color: SEV[sev]?.fg, border: `1px solid ${SEV[sev]?.border}`, flexShrink: 0 }),
  meta: { fontSize: 12, color: "#64748b", marginTop: 4 },
  readBtn: { marginLeft: "auto", background: "none", border: "1px solid #1e2535", borderRadius: 6, color: "#64748b", cursor: "pointer", padding: "3px 10px", fontSize: 12 },
  locTag: { fontSize: 11, color: "#60a5fa", background: "#1e2a45", borderRadius: 4, padding: "1px 6px" },
};

export default function Alerts() {
  const { selectedLocationId, locations, refreshUnread } = useApp();
  const [alerts, setAlerts] = useState([]);
  const [sev, setSev] = useState("all");
  const [unreadOnly, setUnreadOnly] = useState(false);
  const locName = selectedLocationId ? locations.find((l) => l.id === selectedLocationId)?.name : "все локации";

  const load = () => {
    const params = { hours: 168 };
    if (unreadOnly) params.unread_only = true;
    if (sev !== "all") params.severity = sev;
    if (selectedLocationId) params.location_id = selectedLocationId;
    api.alerts(params).then(setAlerts).catch(console.error);
  };

  useEffect(load, [sev, unreadOnly, selectedLocationId]);

  const markRead = async (id) => { await api.markAlertRead(id); load(); refreshUnread(); };
  const markAll = async () => { await api.markAllAlertsRead(selectedLocationId); load(); refreshUnread(); };
  const getLocName = (id) => id ? (locations.find((l) => l.id === id)?.name || `#${id}`) : null;

  return (
    <div>
      <h1 style={s.h1}>События — {locName}</h1>
      <div style={s.toolbar}>
        {["all","critical","warning","info"].map((v) => (
          <button key={v} style={s.btn(sev === v)} onClick={() => setSev(v)}>
            {v === "all" ? "Все" : v}
          </button>
        ))}
        <button style={s.btn(unreadOnly)} onClick={() => setUnreadOnly((x) => !x)}>Непрочитанные</button>
        <button style={{ ...s.btn(false), marginLeft: "auto" }} onClick={markAll}>Прочитать все</button>
      </div>

      {alerts.length === 0 && <p style={{ color: "#64748b", fontSize: 13 }}>Событий нет</p>}
      {alerts.map((a) => (
        <div key={a.id} style={s.card(a.severity, a.is_read)}>
          <span style={s.badge(a.severity)}>{a.severity.toUpperCase()}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 500, color: SEV[a.severity]?.fg || "#e2e8f0" }}>
              {a.message}
              {!selectedLocationId && a.location_id && (
                <span style={{ ...s.locTag, marginLeft: 8 }}>{getLocName(a.location_id)}</span>
              )}
            </div>
            {a.detail && <div style={{ fontSize: 12, opacity: 0.7, marginTop: 3, color: "#cbd5e1" }}>{a.detail}</div>}
            <div style={s.meta}>
              {a.alert_type} · {new Date(a.timestamp).toLocaleString("ru")}
              {a.device_mac && ` · ${a.device_mac}`}
            </div>
          </div>
          {!a.is_read && <button style={s.readBtn} onClick={() => markRead(a.id)}>✓</button>}
        </div>
      ))}
    </div>
  );
}
