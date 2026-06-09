import React, { useEffect, useState } from "react";
import { api } from "../api/client";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const COLORS = ["#3b82f6","#6366f1","#8b5cf6","#a855f7","#ec4899","#ef4444","#f97316","#eab308","#22c55e","#14b8a6"];

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 20, color: "#f1f5f9" },
  tabs: { display: "flex", gap: 8, marginBottom: 24 },
  tab: (a) => ({ padding: "6px 16px", borderRadius: 6, border: "1px solid #1e2535", background: a ? "#1d4ed8" : "#161b27", color: a ? "#fff" : "#94a3b8", cursor: "pointer", fontSize: 13 }),
  grid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 28 },
  card: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: 20 },
  cardTitle: { fontSize: 14, fontWeight: 600, color: "#94a3b8", marginBottom: 14 },
  row: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid #1e2535", fontSize: 13 },
  domain: { color: "#e2e8f0", fontFamily: "monospace" },
  count: { color: "#60a5fa", fontWeight: 600 },
};

export default function DNSActivity() {
  const [period, setPeriod] = useState("24h");
  const [domains, setDomains] = useState([]);
  const [devStats, setDevStats] = useState([]);

  useEffect(() => {
    api.topDomains(period).then(setDomains).catch(console.error);
    api.topDevicesDNS(period).then(setDevStats).catch(console.error);
  }, [period]);

  return (
    <div>
      <h1 style={s.h1}>DNS-активность</h1>
      <div style={s.tabs}>
        {["1h","24h","7d"].map((p) => (
          <button key={p} style={s.tab(period === p)} onClick={() => setPeriod(p)}>
            {p === "1h" ? "1 час" : p === "24h" ? "24 часа" : "7 дней"}
          </button>
        ))}
      </div>

      <div style={s.grid}>
        {/* Top domains */}
        <div style={s.card}>
          <div style={s.cardTitle}>Топ доменов</div>
          {domains.slice(0, 15).map((d, i) => (
            <div key={d.domain} style={s.row}>
              <span style={{ color: "#64748b", marginRight: 8, fontSize: 12 }}>{i + 1}.</span>
              <span style={s.domain}>{d.domain}</span>
              <span style={s.count}>{d.count}</span>
            </div>
          ))}
          {domains.length === 0 && <span style={{ color: "#64748b", fontSize: 13 }}>Нет данных</span>}
        </div>

        {/* Top devices */}
        <div style={s.card}>
          <div style={s.cardTitle}>Активность устройств</div>
          {devStats.length > 0 && (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={devStats} layout="vertical" margin={{ left: 0, right: 20 }}>
                <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} />
                <YAxis type="category" dataKey="friendly_name" width={110} tick={{ fill: "#94a3b8", fontSize: 12 }}
                  tickFormatter={(v, i) => v || devStats[i]?.device_mac?.slice(-8) || "?"} />
                <Tooltip
                  contentStyle={{ background: "#1e2535", border: "none", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#e2e8f0" }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {devStats.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
          {devStats.length === 0 && <span style={{ color: "#64748b", fontSize: 13 }}>Нет данных</span>}
        </div>
      </div>

      {/* Chart domains */}
      <div style={s.card}>
        <div style={s.cardTitle}>График топ-10 доменов</div>
        {domains.length > 0 ? (
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={domains.slice(0, 10)} margin={{ bottom: 50 }}>
              <XAxis dataKey="domain" tick={{ fill: "#64748b", fontSize: 11, angle: -30, textAnchor: "end" }} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#1e2535", border: "none", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {domains.slice(0, 10).map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <span style={{ color: "#64748b", fontSize: 13 }}>Нет данных</span>
        )}
      </div>
    </div>
  );
}
