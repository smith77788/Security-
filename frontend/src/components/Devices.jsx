import React, { useEffect, useState } from "react";
import { api } from "../api/client";

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#f1f5f9" },
  filters: { display: "flex", gap: 10, marginBottom: 20 },
  btn: (active) => ({
    padding: "6px 14px", borderRadius: 6, border: "1px solid #1e2535",
    background: active ? "#1d4ed8" : "#161b27", color: active ? "#fff" : "#94a3b8",
    cursor: "pointer", fontSize: 13,
  }),
  table: { width: "100%", borderCollapse: "collapse" },
  th: { textAlign: "left", padding: "10px 12px", fontSize: 12, color: "#64748b", textTransform: "uppercase", borderBottom: "1px solid #1e2535", letterSpacing: 1 },
  td: { padding: "10px 12px", fontSize: 13, color: "#cbd5e1", borderBottom: "1px solid #1e2535" },
  newBadge: { padding: "2px 8px", borderRadius: 4, background: "#78350f", color: "#fde68a", fontSize: 11, fontWeight: 600 },
  input: { background: "#0f1117", border: "1px solid #1e2535", borderRadius: 6, color: "#e2e8f0", padding: "4px 8px", fontSize: 13, width: 160 },
};

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [filter, setFilter] = useState("all");
  const [editing, setEditing] = useState({});

  const load = () => {
    const params = filter === "new" ? { new_only: true } : filter === "active" ? { active_only: true } : {};
    api.devices(params).then(setDevices).catch(console.error);
  };

  useEffect(load, [filter]);

  const saveName = async (id, name) => {
    await api.updateDevice(id, { friendly_name: name });
    setEditing((e) => ({ ...e, [id]: undefined }));
    load();
  };

  const ack = async (id) => {
    await api.acknowledgeDevice(id);
    load();
  };

  return (
    <div>
      <h1 style={s.h1}>Устройства в сети</h1>
      <div style={s.filters}>
        {["all", "active", "new"].map((f) => (
          <button key={f} style={s.btn(filter === f)} onClick={() => setFilter(f)}>
            {f === "all" ? "Все" : f === "active" ? "Активные" : "Новые"}
          </button>
        ))}
      </div>
      <table style={s.table}>
        <thead>
          <tr>
            {["Имя / Vendor", "MAC", "IP", "Hostname", "Последний раз", "Статус", ""].map((h) => (
              <th key={h} style={s.th}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.id}>
              <td style={s.td}>
                {editing[d.id] !== undefined ? (
                  <input
                    autoFocus
                    style={s.input}
                    value={editing[d.id]}
                    onChange={(e) => setEditing((x) => ({ ...x, [d.id]: e.target.value }))}
                    onBlur={() => saveName(d.id, editing[d.id])}
                    onKeyDown={(e) => e.key === "Enter" && saveName(d.id, editing[d.id])}
                  />
                ) : (
                  <span
                    style={{ cursor: "pointer", color: d.friendly_name ? "#e2e8f0" : "#64748b" }}
                    onClick={() => setEditing((x) => ({ ...x, [d.id]: d.friendly_name || "" }))}
                    title="Нажмите, чтобы задать имя"
                  >
                    {d.friendly_name || d.vendor || "—"}
                    {!d.friendly_name && <span style={{ marginLeft: 4, fontSize: 11, color: "#475569" }}>✎</span>}
                  </span>
                )}
              </td>
              <td style={{ ...s.td, fontFamily: "monospace", fontSize: 12 }}>{d.mac}</td>
              <td style={{ ...s.td, fontFamily: "monospace" }}>{d.ip || "—"}</td>
              <td style={s.td}>{d.hostname || "—"}</td>
              <td style={s.td}>{new Date(d.last_seen).toLocaleString("ru")}</td>
              <td style={s.td}>
                {d.is_new && <span style={s.newBadge}>НОВОЕ</span>}
                {!d.is_new && d.is_active && <span style={{ color: "#22c55e", fontSize: 12 }}>● Активно</span>}
                {!d.is_active && <span style={{ color: "#475569", fontSize: 12 }}>○ Неактивно</span>}
              </td>
              <td style={s.td}>
                {d.is_new && (
                  <button
                    onClick={() => ack(d.id)}
                    style={{ ...s.btn(false), padding: "3px 10px", fontSize: 12 }}
                  >
                    Подтвердить
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {devices.length === 0 && (
        <p style={{ color: "#64748b", marginTop: 20, fontSize: 13 }}>Устройств не найдено</p>
      )}
    </div>
  );
}
