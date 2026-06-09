import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const GRADE_COLOR = { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };

const s = {
  page: {},
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 24, color: "#f1f5f9" },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 28 },
  card: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "20px 24px" },
  cardLabel: { fontSize: 12, color: "#64748b", marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 },
  cardValue: { fontSize: 28, fontWeight: 700, color: "#e2e8f0" },
  scoreCard: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: 24, marginBottom: 28, display: "flex", alignItems: "center", gap: 32 },
  scoreGrade: { fontSize: 72, fontWeight: 900, lineHeight: 1 },
  scoreRight: {},
  scoreTitle: { fontSize: 18, fontWeight: 600, color: "#f1f5f9", marginBottom: 8 },
  detail: { fontSize: 13, color: "#94a3b8", marginBottom: 4 },
  alertRow: { display: "flex", alignItems: "flex-start", gap: 10, padding: "10px 0", borderBottom: "1px solid #1e2535", fontSize: 13 },
  badge: (sev) => ({
    padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, flexShrink: 0,
    background: sev === "critical" ? "#7f1d1d" : sev === "warning" ? "#78350f" : "#1e3a5f",
    color: sev === "critical" ? "#fca5a5" : sev === "warning" ? "#fde68a" : "#93c5fd",
  }),
};

export default function Overview() {
  const [score, setScore] = useState(null);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    api.score().then(setScore).catch(console.error);
    api.alerts({ hours: 24 }).then(setAlerts).catch(console.error);
  }, []);

  const unread = alerts.filter((a) => !a.is_read).length;

  return (
    <div style={s.page}>
      <h1 style={s.h1}>Обзор сети</h1>

      {score && (
        <>
          <div style={s.scoreCard}>
            <div style={{ ...s.scoreGrade, color: GRADE_COLOR[score.grade] || "#e2e8f0" }}>
              {score.grade}
            </div>
            <div style={s.scoreRight}>
              <div style={s.scoreTitle}>
                Рейтинг безопасности: {score.score}/100
              </div>
              {score.details.map((d, i) => (
                <div key={i} style={s.detail}>• {d}</div>
              ))}
            </div>
          </div>

          <div style={s.grid}>
            <StatCard label="Устройств в сети" value={score.total_devices} />
            <StatCard label="Новых устройств" value={score.new_devices} color={score.new_devices > 0 ? "#f97316" : undefined} />
            <StatCard label="Непрочитанных событий" value={score.unread_alerts} color={score.unread_alerts > 0 ? "#eab308" : undefined} />
            <StatCard label="Критических (24ч)" value={score.critical_alerts} color={score.critical_alerts > 0 ? "#ef4444" : undefined} />
            <StatCard label="Без имени" value={score.unnamed_devices} color={score.unnamed_devices > 0 ? "#94a3b8" : undefined} />
          </div>
        </>
      )}

      <h2 style={{ fontSize: 16, fontWeight: 600, color: "#f1f5f9", marginBottom: 12 }}>
        Последние события {unread > 0 && <span style={{ background: "#ef4444", color: "#fff", borderRadius: 10, padding: "1px 8px", fontSize: 12, marginLeft: 8 }}>{unread}</span>}
      </h2>
      <div style={s.card}>
        {alerts.length === 0 && <div style={{ color: "#64748b", fontSize: 13 }}>Событий нет</div>}
        {alerts.slice(0, 8).map((a) => (
          <div key={a.id} style={s.alertRow}>
            <span style={s.badge(a.severity)}>{a.severity}</span>
            <span style={{ color: "#cbd5e1" }}>{a.message}</span>
            <span style={{ marginLeft: "auto", color: "#475569", fontSize: 12, flexShrink: 0 }}>
              {new Date(a.timestamp).toLocaleString("ru")}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={s.card}>
      <div style={s.cardLabel}>{label}</div>
      <div style={{ ...s.cardValue, color: color || "#e2e8f0" }}>{value ?? "—"}</div>
    </div>
  );
}
