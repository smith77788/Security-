import React, { useState, useEffect, useCallback } from "react";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend,
} from "recharts";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

function fmtBytes(b) {
  if (!b) return "0 Б";
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + " ГБ";
  if (b >= 1048576) return (b / 1048576).toFixed(1) + " МБ";
  if (b >= 1024) return (b / 1024).toFixed(0) + " КБ";
  return b + " Б";
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "#0d111c", border: "1px solid #334155", borderRadius: 8,
      padding: "8px 12px", fontSize: 12, color: "#e2e8f0",
    }}>
      <div style={{ color: "#64748b", marginBottom: 4 }}>{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ color: p.color }}>
          {p.name}: {fmtBytes(p.value)}
        </div>
      ))}
    </div>
  );
}

export default function Bandwidth() {
  const { selectedLocationId } = useApp();
  const [timeline, setTimeline] = useState([]);
  const [topData, setTopData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hours, setHours] = useState(1);
  const [view, setView] = useState("timeline");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const locParam = selectedLocationId ? { location_id: selectedLocationId } : {};
      const [tl, top] = await Promise.all([
        api.bandwidthTimeline({ hours, ...locParam }),
        api.bandwidthTop({ minutes: hours * 60, ...locParam }),
      ]);
      setTimeline(tl);
      setTopData(top);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedLocationId, hours]);

  useEffect(() => { load(); }, [load]);

  // Timeline data: [{ts, bytes_up, bytes_down}] → format time label
  const chartData = timeline.map((row) => ({
    time: (() => {
      try {
        const d = new Date(row.ts);
        return d.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
      } catch { return row.ts; }
    })(),
    upload: row.bytes_up || 0,
    download: row.bytes_down || 0,
  }));

  // Top consumers: [{mac, ip, name, bytes_up, bytes_down, total}]
  const barData = topData.slice(0, 10).map((r) => ({
    name: (r.name || r.ip || r.mac || "?").slice(0, 18),
    up: r.bytes_up || 0,
    down: r.bytes_down || 0,
  }));

  const totalUp = topData.reduce((s, r) => s + (r.bytes_up || 0), 0);
  const totalDown = topData.reduce((s, r) => s + (r.bytes_down || 0), 0);

  const s = {
    container: { display: "flex", flexDirection: "column", gap: 20 },
    header: { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" },
    title: { fontSize: 20, fontWeight: 700, color: "#e2e8f0" },
    pill: (active) => ({
      padding: "5px 14px", borderRadius: 20, border: "1px solid #334155",
      background: active ? "#1e3a5f" : "#1e293b",
      color: active ? "#60a5fa" : "#64748b", cursor: "pointer", fontSize: 12,
    }),
    select: {
      padding: "5px 10px", borderRadius: 6, border: "1px solid #334155",
      background: "#1e293b", color: "#94a3b8", fontSize: 12,
    },
    card: {
      background: "#0d111c", borderRadius: 12, border: "1px solid #1e2a45",
      padding: 20,
    },
    cardTitle: { fontSize: 13, fontWeight: 600, color: "#64748b", marginBottom: 16, textTransform: "uppercase", letterSpacing: 0.5 },
    statsRow: { display: "flex", gap: 12, flexWrap: "wrap" },
    statCard: {
      flex: "1 1 120px", background: "#0a0e18", borderRadius: 8,
      border: "1px solid #1e2a45", padding: "12px 16px",
    },
    statLabel: { fontSize: 10, color: "#475569", textTransform: "uppercase", letterSpacing: 0.5 },
    statVal: { fontSize: 18, fontWeight: 700, color: "#e2e8f0", marginTop: 4 },
    empty: { textAlign: "center", color: "#475569", padding: 40 },
  };

  return (
    <div style={s.container}>
      <div style={s.header}>
        <span style={s.title}>📊 Трафик</span>
        <div style={{ display: "flex", gap: 6 }}>
          <button style={s.pill(view === "timeline")} onClick={() => setView("timeline")}>Хронология</button>
          <button style={s.pill(view === "top")} onClick={() => setView("top")}>Топ устройств</button>
        </div>
        <select style={s.select} value={hours} onChange={(e) => setHours(+e.target.value)}>
          <option value={1}>Последний час</option>
          <option value={3}>3 часа</option>
          <option value={6}>6 часов</option>
          <option value={12}>12 часов</option>
          <option value={24}>24 часа</option>
        </select>
        <button style={{ ...s.pill(false), marginLeft: "auto" }} onClick={load}>Обновить</button>
      </div>

      {error && (
        <div style={{ padding: 14, background: "#450a0a", borderRadius: 8, color: "#f87171", fontSize: 13 }}>
          Ошибка: {error}
        </div>
      )}

      <div style={s.statsRow}>
        {[
          { label: "Всего отправлено", val: fmtBytes(totalUp), color: "#3b82f6" },
          { label: "Всего получено", val: fmtBytes(totalDown), color: "#10b981" },
          { label: "Итого", val: fmtBytes(totalUp + totalDown), color: "#94a3b8" },
          { label: "Устройств", val: topData.length, color: "#f59e0b" },
        ].map((item) => (
          <div key={item.label} style={s.statCard}>
            <div style={s.statLabel}>{item.label}</div>
            <div style={{ ...s.statVal, color: item.color }}>{item.val}</div>
          </div>
        ))}
      </div>

      {loading ? (
        <div style={{ ...s.card, textAlign: "center", color: "#475569", padding: 50 }}>Загрузка данных...</div>
      ) : view === "timeline" ? (
        <div style={s.card}>
          <div style={s.cardTitle}>Трафик по времени (5-мин интервалы)</div>
          {chartData.length === 0 ? (
            <div style={s.empty}>Нет данных за выбранный период</div>
          ) : (
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={chartData} margin={{ top: 5, right: 20, bottom: 5, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a45" />
                <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} interval="preserveStartEnd" />
                <YAxis tickFormatter={fmtBytes} tick={{ fill: "#64748b", fontSize: 10 }} width={75} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line
                  type="monotone" dataKey="download" name="↓ Получено"
                  stroke="#10b981" dot={false} strokeWidth={2} connectNulls
                />
                <Line
                  type="monotone" dataKey="upload" name="↑ Отправлено"
                  stroke="#3b82f6" dot={false} strokeWidth={2} connectNulls
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      ) : (
        <div style={s.card}>
          <div style={s.cardTitle}>Топ устройств по трафику</div>
          {barData.length === 0 ? (
            <div style={s.empty}>Нет данных</div>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(220, barData.length * 36)}>
              <BarChart data={barData} layout="vertical" margin={{ top: 5, right: 30, bottom: 5, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a45" horizontal={false} />
                <XAxis type="number" tickFormatter={fmtBytes} tick={{ fill: "#64748b", fontSize: 10 }} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} width={130} />
                <Tooltip
                  formatter={(v) => fmtBytes(v)}
                  contentStyle={{ background: "#0d111c", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="down" name="↓ Получено" fill="#10b981" radius={[0, 3, 3, 0]} />
                <Bar dataKey="up" name="↑ Отправлено" fill="#3b82f6" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      )}
    </div>
  );
}
