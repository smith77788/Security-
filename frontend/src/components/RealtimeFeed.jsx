import React from "react";
import { useApp } from "../context/AppContext";

const TYPE_META = {
  alert:           { icon: "🚨", label: "Событие" },
  new_device:      { icon: "📡", label: "Новое устройство" },
  location_status: { icon: "📍", label: "Статус локации" },
  score_update:    { icon: "📊", label: "Рейтинг обновлён" },
};

const SEV_COLOR = { critical: "#fca5a5", warning: "#fde68a", info: "#93c5fd" };

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 6, color: "#f1f5f9" },
  sub: { fontSize: 13, color: "#64748b", marginBottom: 22 },
  feed: { display: "flex", flexDirection: "column", gap: 8 },
  item: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 10, padding: "12px 16px", display: "flex", gap: 14, alignItems: "flex-start" },
  icon: { fontSize: 22, flexShrink: 0 },
  body: { flex: 1 },
  type: { fontSize: 11, color: "#475569", textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 },
  msg: { fontSize: 13, color: "#e2e8f0" },
  loc: { fontSize: 12, color: "#60a5fa", marginTop: 2 },
  time: { fontSize: 12, color: "#475569", flexShrink: 0 },
  empty: { color: "#475569", fontSize: 13, padding: "40px 0", textAlign: "center" },
  pulse: { display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: "#22c55e", marginRight: 8, animation: "pulse 1.5s infinite" },
};

export default function RealtimeFeed() {
  const { liveEvents } = useApp();

  return (
    <div>
      <h1 style={s.h1}>
        <span style={s.pulse} />
        Live Feed
        <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
      </h1>
      <p style={s.sub}>События в реальном времени по всем локациям. Данные обновляются мгновенно через WebSocket.</p>

      <div style={s.feed}>
        {liveEvents.length === 0 && (
          <div style={s.empty}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>⚡</div>
            Ожидание событий… Они появятся здесь в реальном времени.
          </div>
        )}
        {liveEvents.map((e) => {
          const meta = TYPE_META[e.type] || { icon: "ℹ️", label: e.type };
          const sev = e.payload?.severity;
          const msg = e.type === "alert"
            ? e.payload?.message
            : e.type === "new_device"
            ? `${e.payload?.vendor || "Устройство"} (${e.payload?.mac})`
            : e.type === "location_status"
            ? `${e.location_name}: ${e.payload?.online ? "онлайн" : "оффлайн"}`
            : e.type === "score_update"
            ? `${e.location_name}: рейтинг ${e.payload?.score} (${e.payload?.grade})`
            : JSON.stringify(e.payload);

          return (
            <div key={e.id} style={s.item}>
              <span style={s.icon}>{meta.icon}</span>
              <div style={s.body}>
                <div style={s.type}>
                  {meta.label}
                  {sev && <span style={{ marginLeft: 8, color: SEV_COLOR[sev] || "#94a3b8" }}>● {sev}</span>}
                </div>
                <div style={s.msg}>{msg}</div>
                {e.location_name && <div style={s.loc}>{e.location_name}</div>}
              </div>
              <span style={s.time}>{e.ts.toLocaleTimeString("ru")}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
