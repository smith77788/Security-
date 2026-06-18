import React, { useState, useEffect, useCallback } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";
import { formatDistanceToNow } from "date-fns";

function formatBytes(b) {
  if (!b) return "—";
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " ГБ";
  if (b >= 1048576) return (b / 1048576).toFixed(1) + " МБ";
  if (b >= 1024) return (b / 1024).toFixed(1) + " КБ";
  return b + " Б";
}

function ThreatBadge({ conn }) {
  if (!conn.is_threat && !conn.is_tor) return null;
  return (
    <span style={{
      display: "inline-block", padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700,
      background: conn.is_tor ? "#2e1065" : "#450a0a",
      color: conn.is_tor ? "#a855f7" : "#f87171",
      border: `1px solid ${conn.is_tor ? "#7e22ce" : "#7f1d1d"}`,
      marginRight: 4,
    }}>
      {conn.is_tor ? "TOR" : "⚠ УГРОЗА"}
    </span>
  );
}

function CountryFlag({ countryCode }) {
  if (!countryCode) return <span style={{ color: "#475569" }}>—</span>;
  const flag = countryCode.toUpperCase().replace(/./g, (c) =>
    String.fromCodePoint(c.charCodeAt(0) + 127397)
  );
  return <span title={countryCode}>{flag}</span>;
}

export default function Connections() {
  const { selectedLocationId } = useApp();
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [threatOnly, setThreatOnly] = useState(false);
  const [hours, setHours] = useState(24);
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const data = await api.connections({
        ...(selectedLocationId && { location_id: selectedLocationId }),
        threat_only: threatOnly,
        hours,
        limit: 200,
      });
      setConnections(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedLocationId, threatOnly, hours]);

  useEffect(() => { load(); }, [load]);

  const threatCount = connections.filter((c) => c.is_threat || c.is_tor).length;

  const s = {
    container: { display: "flex", flexDirection: "column", gap: 16 },
    header: { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" },
    title: { fontSize: 20, fontWeight: 700, color: "#e2e8f0" },
    pill: (active) => ({
      padding: "5px 12px", borderRadius: 20, border: "1px solid #334155",
      background: active ? "#1e3a5f" : "#1e293b",
      color: active ? "#60a5fa" : "#64748b", cursor: "pointer", fontSize: 12,
    }),
    select: {
      padding: "5px 10px", borderRadius: 6, border: "1px solid #334155",
      background: "#1e293b", color: "#94a3b8", fontSize: 12,
    },
    card: { background: "#0d111c", borderRadius: 12, border: "1px solid #1e2a45", overflow: "hidden" },
    table: { width: "100%", borderCollapse: "collapse" },
    th: {
      padding: "10px 14px", textAlign: "left", fontSize: 11, color: "#64748b",
      fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5,
      borderBottom: "1px solid #1e2a45", background: "#0a0e18",
    },
    td: (threat) => ({
      padding: "10px 14px", fontSize: 12.5, color: "#cbd5e1",
      borderBottom: "1px solid #1a2035",
      background: threat ? "rgba(239,68,68,0.04)" : "transparent",
    }),
    mono: { fontFamily: "monospace", fontSize: 12 },
    tag: (c, bg) => ({
      display: "inline-block", padding: "1px 6px", borderRadius: 4, fontSize: 10,
      background: bg, color: c, fontWeight: 600, marginLeft: 4,
    }),
    expandedRow: {
      padding: "12px 18px", background: "#0a0e18",
      borderBottom: "1px solid #1e2a45", fontSize: 12, color: "#94a3b8",
    },
    stat: { display: "flex", gap: 24, flexWrap: "wrap" },
    statItem: { display: "flex", flexDirection: "column", gap: 2 },
    statLabel: { fontSize: 10, color: "#475569", textTransform: "uppercase" },
    statVal: { fontSize: 13, color: "#e2e8f0", fontWeight: 600 },
    empty: { padding: 50, textAlign: "center", color: "#475569" },
  };

  return (
    <div style={s.container}>
      <div style={s.header}>
        <span style={s.title}>🔗 Соединения</span>
        {threatCount > 0 && (
          <span style={{ padding: "3px 10px", borderRadius: 20, background: "#450a0a", color: "#f87171", fontSize: 12, fontWeight: 700 }}>
            ⚠ {threatCount} угроз
          </span>
        )}
        <button
          style={s.pill(threatOnly)}
          onClick={() => setThreatOnly(!threatOnly)}
        >
          Только угрозы
        </button>
        <select style={s.select} value={hours} onChange={(e) => setHours(+e.target.value)}>
          <option value={1}>Последний час</option>
          <option value={6}>6 часов</option>
          <option value={24}>24 часа</option>
          <option value={72}>3 дня</option>
          <option value={168}>7 дней</option>
        </select>
        <button
          style={{ ...s.pill(false), marginLeft: "auto" }}
          onClick={load}
        >
          Обновить
        </button>
      </div>

      {error && (
        <div style={{ padding: 16, background: "#450a0a", borderRadius: 8, color: "#f87171", fontSize: 13 }}>
          Ошибка: {error}
        </div>
      )}

      <div style={s.card}>
        {loading ? (
          <div style={s.empty}>Загрузка...</div>
        ) : connections.length === 0 ? (
          <div style={s.empty}>Нет соединений за выбранный период</div>
        ) : (
          <table style={s.table}>
            <thead>
              <tr>
                <th style={s.th}>Источник</th>
                <th style={s.th}>Назначение</th>
                <th style={s.th}>Страна / Орг</th>
                <th style={s.th}>Протокол</th>
                <th style={s.th}>↑ Отправлено</th>
                <th style={s.th}>↓ Получено</th>
                <th style={s.th}>Когда</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((c) => {
                const isExp = expanded === c.id;
                const threat = c.is_threat || c.is_tor;
                return (
                  <React.Fragment key={c.id}>
                    <tr
                      style={{ cursor: "pointer" }}
                      onClick={() => setExpanded(isExp ? null : c.id)}
                    >
                      <td style={s.td(threat)}>
                        <span style={s.mono}>{c.src_ip}</span>
                      </td>
                      <td style={s.td(threat)}>
                        <ThreatBadge conn={c} />
                        <span style={s.mono}>{c.tls_sni || c.dst_ip}</span>
                        {c.tls_sni && (
                          <span style={{ color: "#475569", marginLeft: 4, fontSize: 11 }}>({c.dst_ip})</span>
                        )}
                        <span style={s.tag("#94a3b8", "#1e293b")}>:{c.dst_port}</span>
                      </td>
                      <td style={s.td(threat)}>
                        <CountryFlag countryCode={c.country_code} />
                        {" "}
                        <span style={{ color: "#64748b", fontSize: 11 }}>{c.org || c.country || "—"}</span>
                      </td>
                      <td style={s.td(threat)}>
                        <span style={s.tag("#60a5fa", "#172554")}>{c.protocol}</span>
                      </td>
                      <td style={s.td(threat)}>{formatBytes(c.bytes_out)}</td>
                      <td style={s.td(threat)}>{formatBytes(c.bytes_in)}</td>
                      <td style={s.td(threat)}>
                        <span style={{ fontSize: 11, color: "#475569" }}>
                          {c.last_seen
                            ? formatDistanceToNow(new Date(c.last_seen), { addSuffix: true })
                            : "—"}
                        </span>
                      </td>
                    </tr>
                    {isExp && (
                      <tr>
                        <td colSpan={7} style={s.expandedRow}>
                          <div style={s.stat}>
                            <div style={s.statItem}>
                              <span style={s.statLabel}>Первое соединение</span>
                              <span style={s.statVal}>{c.first_seen ? new Date(c.first_seen).toLocaleString("ru") : "—"}</span>
                            </div>
                            <div style={s.statItem}>
                              <span style={s.statLabel}>Последнее соединение</span>
                              <span style={s.statVal}>{c.last_seen ? new Date(c.last_seen).toLocaleString("ru") : "—"}</span>
                            </div>
                            <div style={s.statItem}>
                              <span style={s.statLabel}>ASN</span>
                              <span style={s.statVal}>{c.asn || "—"}</span>
                            </div>
                            <div style={s.statItem}>
                              <span style={s.statLabel}>Организация</span>
                              <span style={s.statVal}>{c.org || "—"}</span>
                            </div>
                            <div style={s.statItem}>
                              <span style={s.statLabel}>TLS SNI</span>
                              <span style={s.statVal}>{c.tls_sni || "нет"}</span>
                            </div>
                            {c.threat_reason && (
                              <div style={s.statItem}>
                                <span style={s.statLabel}>Причина угрозы</span>
                                <span style={{ ...s.statVal, color: "#f87171" }}>{c.threat_reason}</span>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      <div style={{ fontSize: 11, color: "#334155", textAlign: "right" }}>
        Показано {connections.length} соединений · Нажмите на строку для деталей
      </div>
    </div>
  );
}
