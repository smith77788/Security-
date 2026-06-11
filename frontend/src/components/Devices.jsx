import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#f1f5f9" },
  filters: { display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" },
  btn: (a) => ({
    padding: "6px 14px", borderRadius: 6, border: "1px solid #1e2535",
    background: a ? "#1d4ed8" : "#161b27", color: a ? "#fff" : "#94a3b8",
    cursor: "pointer", fontSize: 13,
  }),
  tableWrap: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse", minWidth: 720 },
  th: { textAlign: "left", padding: "10px 12px", fontSize: 11, color: "#64748b", textTransform: "uppercase", borderBottom: "1px solid #1e2535", letterSpacing: 1 },
  td: { padding: "10px 12px", fontSize: 13, color: "#cbd5e1", borderBottom: "1px solid #1e2535" },
  newBadge: { padding: "2px 8px", borderRadius: 4, background: "#78350f", color: "#fde68a", fontSize: 11, fontWeight: 600 },
  blockedBadge: { padding: "2px 8px", borderRadius: 4, background: "#450a0a", color: "#f87171", fontSize: 11, fontWeight: 700 },
  input: { background: "#0f1117", border: "1px solid #1e2535", borderRadius: 6, color: "#e2e8f0", padding: "4px 8px", fontSize: 13, width: 160 },
  smallBtn: (danger) => ({
    padding: "3px 10px", fontSize: 12, borderRadius: 6, cursor: "pointer",
    border: `1px solid ${danger ? "#7f1d1d" : "#1e2535"}`,
    background: danger ? "#2a0a0a" : "#161b27",
    color: danger ? "#f87171" : "#94a3b8",
    marginRight: 6,
  }),
};

export default function Devices() {
  const { selectedLocationId, locations } = useApp();
  const [devices, setDevices] = useState([]);
  const [blockedMacs, setBlockedMacs] = useState(new Set());
  const [filter, setFilter] = useState("all");
  const [editing, setEditing] = useState({});

  const locationName = (id) => locations.find((l) => l.id === id)?.name || "—";

  const load = () => {
    const params = { ...(selectedLocationId ? { location_id: selectedLocationId } : {}) };
    if (filter === "new") params.new_only = true;
    if (filter === "active") params.active_only = true;
    api.devices(params).then(setDevices).catch(console.error);
    api.blockedDevices()
      .then((rows) => setBlockedMacs(new Set(rows.map((r) => r.mac))))
      .catch(() => {});
  };

  useEffect(load, [filter, selectedLocationId]);

  const saveName = async (id, name) => {
    await api.updateDevice(id, { friendly_name: name });
    setEditing((e) => ({ ...e, [id]: undefined }));
    load();
  };

  const ack = async (id) => {
    await api.acknowledgeDevice(id);
    load();
  };

  const block = async (d) => {
    const reason = window.prompt(
      `Заблокировать ${d.friendly_name || d.vendor || d.mac}?\n\nУкажите причину (или оставьте пустым):`
    );
    if (reason === null) return;
    await api.blockDevice(d.id, reason || "Заблокировано вручную");
    load();
  };

  const unblock = async (d) => {
    await api.unblockDevice(d.id);
    load();
  };

  const shown = filter === "blocked"
    ? devices.filter((d) => blockedMacs.has(d.mac))
    : devices;

  return (
    <div>
      <h1 style={s.h1}>Устройства {selectedLocationId ? `— ${locationName(selectedLocationId)}` : "— все локации"}</h1>
      <div style={s.filters}>
        {["all", "active", "new", "blocked"].map((f) => (
          <button key={f} style={s.btn(filter === f)} onClick={() => setFilter(f)}>
            {f === "all" ? "Все" : f === "active" ? "Активные" : f === "new" ? "Новые" : "Заблокированные"}
          </button>
        ))}
        <span style={{ marginLeft: "auto", color: "#475569", fontSize: 13, alignSelf: "center" }}>
          {shown.length} устройств
        </span>
      </div>
      <div style={s.tableWrap}>
        <table style={s.table}>
          <thead>
            <tr>
              {["Имя / Vendor", "MAC", "IP", "Hostname", !selectedLocationId && "Локация", "Последний раз", "Статус", "Действия"].filter(Boolean).map((h) => (
                <th key={h} style={s.th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((d) => {
              const isBlocked = blockedMacs.has(d.mac);
              return (
                <tr key={d.id} style={isBlocked ? { background: "rgba(239,68,68,0.04)" } : undefined}>
                  <td style={s.td}>
                    {editing[d.id] !== undefined ? (
                      <input
                        autoFocus style={s.input}
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
                  {!selectedLocationId && (
                    <td style={s.td}>
                      {d.location_id ? (
                        <span style={{ color: "#60a5fa", fontSize: 12 }}>
                          {locationName(d.location_id)}
                        </span>
                      ) : "—"}
                    </td>
                  )}
                  <td style={s.td}>{new Date(d.last_seen).toLocaleString("ru")}</td>
                  <td style={s.td}>
                    {isBlocked && <span style={s.blockedBadge}>⛔ БЛОК</span>}{" "}
                    {d.is_new && <span style={s.newBadge}>НОВОЕ</span>}
                    {!d.is_new && !isBlocked && d.is_active && <span style={{ color: "#22c55e", fontSize: 12 }}>● Активно</span>}
                    {!d.is_active && !isBlocked && <span style={{ color: "#475569", fontSize: 12 }}>○ Неактивно</span>}
                  </td>
                  <td style={{ ...s.td, whiteSpace: "nowrap" }}>
                    {d.is_new && (
                      <button onClick={() => ack(d.id)} style={s.smallBtn(false)}>
                        Подтвердить
                      </button>
                    )}
                    {isBlocked ? (
                      <button onClick={() => unblock(d)} style={s.smallBtn(false)}>
                        Разблокировать
                      </button>
                    ) : (
                      <button onClick={() => block(d)} style={s.smallBtn(true)}>
                        ⛔ Блок
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {shown.length === 0 && <p style={{ color: "#64748b", marginTop: 20, fontSize: 13 }}>Устройств не найдено</p>}
      <p style={{ color: "#334155", marginTop: 14, fontSize: 12 }}>
        ⛔ Блокировка — режим наблюдения: система создаёт критическое событие при каждом появлении устройства в сети.
      </p>
    </div>
  );
}
