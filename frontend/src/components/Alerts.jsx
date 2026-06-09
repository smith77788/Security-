import React, { useEffect, useState } from "react";
import { api } from "../api/client";

const SEV_STYLE = {
  critical: { background: "#7f1d1d", color: "#fca5a5", border: "1px solid #991b1b" },
  warning:  { background: "#78350f", color: "#fde68a", border: "1px solid #92400e" },
  info:     { background: "#1e3a5f", color: "#93c5fd", border: "1px solid #1e40af" },
};

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#f1f5f9" },
  toolbar: { display: "flex", gap: 10, marginBottom: 20, alignItems: "center" },
  btn: (a) => ({ padding: "6px 14px", borderRadius: 6, border: "1px solid #1e2535", background: a ? "#1d4ed8" : "#161b27", color: a ? "#fff" : "#94a3b8", cursor: "pointer", fontSize: 13 }),
  card: { borderRadius: 10, padding: "14px 18px", marginBottom: 10, display: "flex", alignItems: "flex-start", gap: 12 },
  meta: { fontSize: 12, color: "#64748b", marginTop: 4 },
  badge: (sev) => ({ padding: "3px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, ...SEV_STYLE[sev] }),
  readBtn: { marginLeft: "auto", background: "none", border: "1px solid #1e2535", borderRadius: 6, color: "#64748b", cursor: "pointer", padding: "3px 10px", fontSize: 12 },
};

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [sev, setSev] = useState("all");
  const [unreadOnly, setUnreadOnly] = useState(false);

  const load = () => {
    const params = { hours: 168 };
    if (unreadOnly) params.unread_only = true;
    if (sev !== "all") params.severity = sev;
    api.alerts(params).then(setAlerts).catch(console.error);
  };

  useEffect(load, [sev, unreadOnly]);

  const markRead = async (id) => {
    await api.markAlertRead(id);
    load();
  };

  const markAll = async () => {
    await api.markAllAlertsRead();
    load();
  };

  return (
    <div>
      <h1 style={s.h1}>События</h1>
      <div style={s.toolbar}>
        {["all", "critical", "warning", "info"].map((v) => (
          <button key={v} style={s.btn(sev === v)} onClick={() => setSev(v)}>
            {v === "all" ? "Все" : v}
          </button>
        ))}
        <button style={s.btn(unreadOnly)} onClick={() => setUnreadOnly((x) => !x)}>
          Непрочитанные
        </button>
        <button style={{ ...s.btn(false), marginLeft: "auto" }} onClick={markAll}>
          Прочитать все
        </button>
      </div>

      {alerts.length === 0 && <p style={{ color: "#64748b", fontSize: 13 }}>Событий нет</p>}

      {alerts.map((a) => (
        <div key={a.id} style={{ ...s.card, ...SEV_STYLE[a.severity], opacity: a.is_read ? 0.55 : 1 }}>
          <span style={s.badge(a.severity)}>{a.severity.toUpperCase()}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 500 }}>{a.message}</div>
            {a.detail && <div style={{ fontSize: 12, opacity: 0.7, marginTop: 3 }}>{a.detail}</div>}
            <div style={s.meta}>
              {a.alert_type} · {new Date(a.timestamp).toLocaleString("ru")}
              {a.device_mac && ` · ${a.device_mac}`}
            </div>
          </div>
          {!a.is_read && (
            <button style={s.readBtn} onClick={() => markRead(a.id)}>✓</button>
          )}
        </div>
      ))}
    </div>
  );
}
