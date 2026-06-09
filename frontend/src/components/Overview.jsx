import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const GRADE_COLOR = { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 22, color: "#f1f5f9" },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: 16, marginBottom: 28 },
  card: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "18px 22px" },
  locCard: (color, offline) => ({
    background: "#161b27", border: `1px solid ${offline ? "#1e2535" : color + "44"}`,
    borderRadius: 12, padding: "18px 22px", cursor: "pointer",
    transition: "border-color .2s",
    opacity: offline ? 0.65 : 1,
  }),
  locHeader: { display: "flex", alignItems: "center", gap: 10, marginBottom: 14 },
  locIcon: { fontSize: 28 },
  locTitle: { fontSize: 15, fontWeight: 700, color: "#f1f5f9" },
  locSub: { fontSize: 12, color: "#64748b", marginTop: 1 },
  scoreRow: { display: "flex", alignItems: "center", gap: 12, marginBottom: 12 },
  gradeCircle: (color) => ({
    width: 44, height: 44, borderRadius: "50%", background: color + "22",
    border: `2px solid ${color}`, display: "flex", alignItems: "center",
    justifyContent: "center", fontSize: 18, fontWeight: 900, color,
    flexShrink: 0,
  }),
  statRow: { display: "flex", gap: 16, flexWrap: "wrap" },
  stat: (warn) => ({ fontSize: 12, color: warn ? "#fde68a" : "#64748b" }),
  statVal: (warn) => ({ fontWeight: 700, color: warn ? "#fde68a" : "#94a3b8" }),
  onlineDot: (on) => ({ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: on ? "#22c55e" : "#475569", marginRight: 5 }),
  globalCard: {
    background: "#161b27", border: "1px solid #1e2535", borderRadius: 12,
    padding: "20px 24px", marginBottom: 24, display: "flex", gap: 28, alignItems: "center",
    flexWrap: "wrap",
  },
  bigGrade: (g) => ({ fontSize: 56, fontWeight: 900, lineHeight: 1, color: GRADE_COLOR[g] || "#e2e8f0" }),
};

function LocationCard({ loc, onClick }) {
  return (
    <div style={s.locCard(loc.color, !loc.is_online)} onClick={() => onClick(loc.id)}>
      <div style={s.locHeader}>
        <span style={s.locIcon}>{loc.icon}</span>
        <div>
          <div style={s.locTitle}>
            <span style={s.onlineDot(loc.is_online)} />
            {loc.name}
          </div>
          <div style={s.locSub}>{loc.is_online ? "Онлайн" : "Оффлайн"}</div>
        </div>
        <div style={{ marginLeft: "auto", ...s.gradeCircle(GRADE_COLOR[loc.grade] || "#94a3b8") }}>
          {loc.grade}
        </div>
      </div>
      <div style={s.statRow}>
        <div style={s.stat(false)}>
          Устройств: <span style={s.statVal(false)}>{loc.active_devices}/{loc.total_devices}</span>
        </div>
        {loc.new_devices > 0 && (
          <div style={s.stat(true)}>Новых: <span style={s.statVal(true)}>{loc.new_devices}</span></div>
        )}
        {loc.unread_alerts > 0 && (
          <div style={s.stat(true)}>Событий: <span style={s.statVal(true)}>{loc.unread_alerts}</span></div>
        )}
        {loc.critical_alerts > 0 && (
          <div style={{ ...s.stat(false), color: "#fca5a5" }}>
            Критических: <span style={{ fontWeight: 700, color: "#fca5a5" }}>{loc.critical_alerts}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function Overview() {
  const { locations, selectedLocationId, setSelectedLocationId } = useApp();
  const [score, setScore] = useState(null);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    api.score(selectedLocationId).then(setScore).catch(console.error);
    api.alerts({ hours: 24, ...(selectedLocationId ? { location_id: selectedLocationId } : {}) })
      .then(setAlerts).catch(console.error);
  }, [selectedLocationId]);

  const totalOnline = locations.filter((l) => l.is_online).length;

  return (
    <div>
      <h1 style={s.h1}>{selectedLocationId ? locations.find((l) => l.id === selectedLocationId)?.name : "Все локации"}</h1>

      {/* Global metrics bar */}
      {!selectedLocationId && (
        <div style={s.globalCard}>
          {score && (
            <>
              <div style={s.bigGrade(score.grade)}>{score.grade}</div>
              <div>
                <div style={{ fontSize: 17, fontWeight: 600, color: "#f1f5f9", marginBottom: 6 }}>
                  Общий рейтинг: {score.score}/100
                </div>
                {score.details.map((d, i) => (
                  <div key={i} style={{ fontSize: 13, color: "#94a3b8" }}>• {d}</div>
                ))}
              </div>
            </>
          )}
          <div style={{ marginLeft: "auto", display: "flex", gap: 24 }}>
            <Kpi label="Локаций онлайн" value={`${totalOnline}/${locations.length}`} ok={totalOnline === locations.length} />
            <Kpi label="Устройств" value={locations.reduce((a, l) => a + l.total_devices, 0)} />
            <Kpi label="Новых" value={locations.reduce((a, l) => a + l.new_devices, 0)} warn={locations.some(l => l.new_devices > 0)} />
            <Kpi label="Алертов" value={locations.reduce((a, l) => a + l.unread_alerts, 0)} warn={locations.some(l => l.unread_alerts > 0)} />
          </div>
        </div>
      )}

      {/* Location cards (all-locations view) */}
      {!selectedLocationId && locations.length > 0 && (
        <div style={s.grid}>
          {locations.map((loc) => (
            <LocationCard key={loc.id} loc={loc} onClick={setSelectedLocationId} />
          ))}
        </div>
      )}

      {/* Per-location score card */}
      {selectedLocationId && score && (
        <div style={s.globalCard}>
          <div style={s.bigGrade(score.grade)}>{score.grade}</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 600, color: "#f1f5f9", marginBottom: 6 }}>
              Рейтинг безопасности: {score.score}/100
            </div>
            {score.details.map((d, i) => (
              <div key={i} style={{ fontSize: 13, color: "#94a3b8" }}>• {d}</div>
            ))}
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 20 }}>
            <Kpi label="Устройств" value={score.total_devices} />
            <Kpi label="Новых" value={score.new_devices} warn={score.new_devices > 0} />
            <Kpi label="Алертов" value={score.unread_alerts} warn={score.unread_alerts > 0} />
          </div>
        </div>
      )}

      {/* Recent alerts */}
      <h2 style={{ fontSize: 15, fontWeight: 600, color: "#94a3b8", marginBottom: 10 }}>Последние события</h2>
      <div style={s.card}>
        {alerts.length === 0 && <div style={{ color: "#475569", fontSize: 13 }}>Событий нет</div>}
        {alerts.slice(0, 10).map((a) => (
          <div key={a.id} style={{ display: "flex", gap: 10, padding: "9px 0", borderBottom: "1px solid #1e2535", fontSize: 13 }}>
            <SevBadge sev={a.severity} />
            <span style={{ color: "#cbd5e1", flex: 1 }}>{a.message}</span>
            <span style={{ color: "#475569", fontSize: 12, flexShrink: 0 }}>
              {new Date(a.timestamp).toLocaleString("ru")}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Kpi({ label, value, warn, ok }) {
  const color = ok === false ? "#ef4444" : ok ? "#22c55e" : warn ? "#fde68a" : "#e2e8f0";
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 26, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "#475569", marginTop: 2 }}>{label}</div>
    </div>
  );
}

function SevBadge({ sev }) {
  const map = { critical: ["#7f1d1d","#fca5a5"], warning: ["#78350f","#fde68a"], info: ["#1e3a5f","#93c5fd"] };
  const [bg, fg] = map[sev] || map.info;
  return (
    <span style={{ background: bg, color: fg, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, flexShrink: 0 }}>
      {sev}
    </span>
  );
}
