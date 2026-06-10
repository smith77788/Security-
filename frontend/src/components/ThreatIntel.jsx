import React, { useState, useEffect, useCallback } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

function StatusCard({ name, count, ok, color }) {
  return (
    <div style={{
      flex: "1 1 160px", background: "#0a0e18", borderRadius: 10,
      border: `1px solid ${ok ? "#1e3a2e" : "#3b1f1f"}`,
      padding: "14px 18px",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span style={{
          width: 8, height: 8, borderRadius: "50%",
          background: ok ? "#22c55e" : "#ef4444", flexShrink: 0,
        }} />
        <span style={{ fontSize: 12, color: "#94a3b8", fontWeight: 600 }}>{name}</span>
      </div>
      <div style={{ fontSize: 22, fontWeight: 800, color: color || (ok ? "#22c55e" : "#ef4444") }}>
        {count !== null && count !== undefined ? count.toLocaleString() : "—"}
      </div>
      <div style={{ fontSize: 10, color: "#475569", marginTop: 2 }}>записей</div>
    </div>
  );
}

function GeoResult({ result }) {
  if (!result) return null;
  return (
    <div style={{ marginTop: 12, background: "#0a0e18", borderRadius: 8, padding: 14, fontSize: 13 }}>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap" }}>
        <div>
          <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Статус</div>
          <div style={{
            fontWeight: 700, fontSize: 15,
            color: result.is_threat ? "#ef4444" : "#22c55e",
          }}>
            {result.is_threat ? "⚠ УГРОЗА" : "✓ Чистый"}
          </div>
        </div>
        {result.is_tor && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Сеть Tor</div>
            <div style={{ color: "#a855f7", fontWeight: 700 }}>Да (Exit Node)</div>
          </div>
        )}
        {result.geo?.country && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Страна</div>
            <div style={{ color: "#e2e8f0" }}>
              {result.flag} {result.geo.country}
            </div>
          </div>
        )}
        {result.geo?.org && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Организация</div>
            <div style={{ color: "#e2e8f0" }}>{result.geo.org}</div>
          </div>
        )}
        {result.geo?.asn && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>ASN</div>
            <div style={{ color: "#94a3b8" }}>{result.geo.asn}</div>
          </div>
        )}
        {result.geo?.city && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Город</div>
            <div style={{ color: "#94a3b8" }}>{result.geo.city}</div>
          </div>
        )}
        {result.threat_reason && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Причина</div>
            <div style={{ color: "#f87171" }}>{result.threat_reason}</div>
          </div>
        )}
      </div>
    </div>
  );
}

function DomainResult({ result }) {
  if (!result) return null;
  return (
    <div style={{ marginTop: 12, background: "#0a0e18", borderRadius: 8, padding: 14, fontSize: 13 }}>
      <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "flex-start" }}>
        <div>
          <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Статус</div>
          <div style={{ fontWeight: 700, fontSize: 15, color: result.is_threat ? "#ef4444" : "#22c55e" }}>
            {result.is_threat ? "⚠ УГРОЗА / ПОДОЗРИТЕЛЬНЫЙ" : "✓ Чистый"}
          </div>
        </div>
        <div>
          <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>DGA-паттерн</div>
          <div style={{ color: result.looks_like_dga ? "#f59e0b" : "#22c55e", fontWeight: 600 }}>
            {result.looks_like_dga ? "⚠ Возможно DGA" : "Нет"}
          </div>
        </div>
        {result.reasons?.length > 0 && (
          <div>
            <div style={{ color: "#475569", fontSize: 10, textTransform: "uppercase" }}>Причины</div>
            <ul style={{ margin: 0, paddingLeft: 16, color: "#f87171" }}>
              {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

function BeaconingTable({ data }) {
  if (!data || data.length === 0) {
    return <div style={{ padding: 30, textAlign: "center", color: "#475569", fontSize: 13 }}>Маяков не обнаружено</div>;
  }
  const s = {
    table: { width: "100%", borderCollapse: "collapse" },
    th: {
      padding: "8px 12px", textAlign: "left", fontSize: 11, color: "#64748b",
      fontWeight: 600, textTransform: "uppercase", borderBottom: "1px solid #1e2a45",
      background: "#0a0e18",
    },
    td: { padding: "10px 12px", fontSize: 12.5, color: "#cbd5e1", borderBottom: "1px solid #1a2035" },
    mono: { fontFamily: "monospace", fontSize: 12 },
  };
  return (
    <table style={s.table}>
      <thead>
        <tr>
          <th style={s.th}>Источник</th>
          <th style={s.th}>Назначение</th>
          <th style={s.th}>Порт</th>
          <th style={s.th}>Кол-во</th>
          <th style={s.th}>Интервал</th>
          <th style={s.th}>CV (норма &lt;0.20)</th>
          <th style={s.th}>Риск</th>
        </tr>
      </thead>
      <tbody>
        {data.map((r, i) => (
          <tr key={i}>
            <td style={s.td}><span style={s.mono}>{r.src_ip}</span></td>
            <td style={s.td}><span style={s.mono}>{r.dst_ip}</span></td>
            <td style={s.td}>{r.dst_port}</td>
            <td style={s.td}>{r.sample_count}</td>
            <td style={s.td}>{r.mean_interval_s ? r.mean_interval_s.toFixed(1) + "с" : "—"}</td>
            <td style={s.td}>
              <span style={{ color: r.cv < 0.1 ? "#ef4444" : r.cv < 0.2 ? "#f59e0b" : "#22c55e", fontWeight: 700 }}>
                {r.cv !== undefined ? r.cv.toFixed(3) : "—"}
              </span>
            </td>
            <td style={s.td}>
              <span style={{
                padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                background: r.cv < 0.1 ? "#450a0a" : r.cv < 0.2 ? "#431407" : "#0f2b1a",
                color: r.cv < 0.1 ? "#f87171" : r.cv < 0.2 ? "#fb923c" : "#4ade80",
              }}>
                {r.cv < 0.1 ? "КРИТИЧНО" : r.cv < 0.2 ? "ВЫСОКИЙ" : "НОРМА"}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ThreatIntel() {
  const { selectedLocationId } = useApp();
  const [status, setStatus] = useState(null);
  const [beaconing, setBeaconing] = useState(null);
  const [ipQuery, setIpQuery] = useState("");
  const [domainQuery, setDomainQuery] = useState("");
  const [ipResult, setIpResult] = useState(null);
  const [domainResult, setDomainResult] = useState(null);
  const [ipLoading, setIpLoading] = useState(false);
  const [domainLoading, setDomainLoading] = useState(false);
  const [beaconLoading, setBeaconLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [tab, setTab] = useState("feeds");

  const loadStatus = useCallback(async () => {
    try { setStatus(await api.intelStatus()); } catch {}
  }, []);

  const loadBeaconing = useCallback(async () => {
    setBeaconLoading(true);
    try {
      const params = selectedLocationId ? `?location_id=${selectedLocationId}` : "";
      setBeaconing(await api.beaconing(params));
    } catch {}
    setBeaconLoading(false);
  }, [selectedLocationId]);

  useEffect(() => { loadStatus(); }, [loadStatus]);
  useEffect(() => { if (tab === "beaconing") loadBeaconing(); }, [tab, loadBeaconing]);

  const lookupIp = async () => {
    if (!ipQuery.trim()) return;
    setIpLoading(true); setIpResult(null);
    try { setIpResult(await api.lookupIp(ipQuery.trim())); }
    catch (e) { setIpResult({ error: e.message }); }
    setIpLoading(false);
  };

  const lookupDomain = async () => {
    if (!domainQuery.trim()) return;
    setDomainLoading(true); setDomainResult(null);
    try { setDomainResult(await api.lookupDomain(domainQuery.trim())); }
    catch (e) { setDomainResult({ error: e.message }); }
    setDomainLoading(false);
  };

  const refreshFeeds = async () => {
    setRefreshing(true);
    try { await api.intelRefresh(); setTimeout(loadStatus, 3000); }
    catch {}
    setRefreshing(false);
  };

  const s = {
    container: { display: "flex", flexDirection: "column", gap: 20 },
    header: { display: "flex", alignItems: "center", gap: 12 },
    title: { fontSize: 20, fontWeight: 700, color: "#e2e8f0" },
    tabs: { display: "flex", gap: 4, borderBottom: "1px solid #1e2a45", marginBottom: 0 },
    tab: (active) => ({
      padding: "9px 18px", fontSize: 13, cursor: "pointer",
      color: active ? "#60a5fa" : "#64748b",
      background: "none", border: "none",
      borderBottom: active ? "2px solid #3b82f6" : "2px solid transparent",
      fontWeight: active ? 600 : 400,
    }),
    card: { background: "#0d111c", borderRadius: 12, border: "1px solid #1e2a45", overflow: "hidden" },
    cardPad: { padding: 20 },
    feedsRow: { display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 },
    lookupRow: { display: "flex", gap: 10, marginBottom: 8 },
    input: {
      flex: 1, padding: "8px 12px", borderRadius: 6, border: "1px solid #334155",
      background: "#1e293b", color: "#e2e8f0", fontSize: 13,
    },
    btn: (c) => ({
      padding: "8px 16px", borderRadius: 6, border: "none", cursor: "pointer",
      background: c || "#1e3a5f", color: "#60a5fa", fontSize: 13, fontWeight: 600,
      opacity: 1,
    }),
    sectionTitle: { fontSize: 13, fontWeight: 600, color: "#64748b", marginBottom: 10, textTransform: "uppercase", letterSpacing: 0.5 },
  };

  const feeds = status?.feeds ? [
    { name: "Feodo C2",          count: status.feeds.feodo_ips?.count,        ok: (status.feeds.feodo_ips?.count || 0) > 0,        color: "#ef4444" },
    { name: "DShield",           count: status.feeds.dshield?.count,           ok: (status.feeds.dshield?.count || 0) > 0,           color: "#f59e0b" },
    { name: "Tor Exit",          count: status.feeds.tor_exits?.count,         ok: (status.feeds.tor_exits?.count || 0) > 0,         color: "#a855f7" },
    { name: "Emerging Threats",  count: status.feeds.emerging_threats?.count,  ok: (status.feeds.emerging_threats?.count || 0) > 0,  color: "#3b82f6" },
    { name: "CINS Army",         count: status.feeds.cins_army?.count,         ok: (status.feeds.cins_army?.count || 0) > 0,         color: "#f97316" },
  ] : [];

  return (
    <div style={s.container}>
      <div style={s.header}>
        <span style={s.title}>🛡 Threat Intelligence</span>
        {status && (
          <span style={{ fontSize: 12, color: "#64748b" }}>
            {(status.bad_ips || 0).toLocaleString()} IP-адресов · {(status.bad_domains || 0).toLocaleString()} доменов · {(status.tor_exits || 0).toLocaleString()} Tor узлов
          </span>
        )}
        <button
          style={{ ...s.btn(), marginLeft: "auto" }}
          onClick={refreshFeeds}
          disabled={refreshing}
        >
          {refreshing ? "Обновляем..." : "Обновить фиды"}
        </button>
      </div>

      <div style={s.card}>
        <div style={{ borderBottom: "1px solid #1e2a45" }}>
          <div style={{ display: "flex" }}>
            {["feeds", "lookup", "beaconing"].map((t) => (
              <button key={t} style={s.tab(tab === t)} onClick={() => setTab(t)}>
                {t === "feeds" ? "📡 Фиды" : t === "lookup" ? "🔍 Поиск" : "📡 Маяки (C2)"}
              </button>
            ))}
          </div>
        </div>

        <div style={s.cardPad}>
          {tab === "feeds" && (
            <>
              <div style={s.sectionTitle}>Статус фидов угроз</div>
              <div style={s.feedsRow}>
                {feeds.length === 0 ? (
                  <div style={{ color: "#475569" }}>Загрузка статуса...</div>
                ) : (
                  feeds.map((f) => (
                    <StatusCard key={f.name} {...f} />
                  ))
                )}
              </div>
              {status?.last_update && (
                <div style={{ fontSize: 11, color: "#475569" }}>
                  Последнее обновление: {new Date(status.last_update).toLocaleString("ru")}
                </div>
              )}
              <div style={{ marginTop: 16, padding: 14, background: "#0a0e18", borderRadius: 8, fontSize: 12, color: "#64748b" }}>
                <div style={{ fontWeight: 600, color: "#94a3b8", marginBottom: 6 }}>Источники данных</div>
                <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
                  <li><strong style={{ color: "#ef4444" }}>Feodo Tracker</strong> — C2 серверы банковских троянов (Emotet, QBot)</li>
                  <li><strong style={{ color: "#f59e0b" }}>DShield</strong> — Топ-20 вредоносных подсетей Internet Storm Center</li>
                  <li><strong style={{ color: "#a855f7" }}>Tor Exit Nodes</strong> — Список выходных узлов сети Tor</li>
                  <li><strong style={{ color: "#3b82f6" }}>Emerging Threats</strong> — Вредоносные домены (abuse.ch)</li>
                  <li><strong style={{ color: "#f97316" }}>CINS Army</strong> — Динамически обновляемые блок-листы IP</li>
                </ul>
              </div>
            </>
          )}

          {tab === "lookup" && (
            <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
              <div style={{ flex: "1 1 300px" }}>
                <div style={s.sectionTitle}>Проверка IP-адреса</div>
                <div style={s.lookupRow}>
                  <input
                    style={s.input}
                    placeholder="Введите IP-адрес..."
                    value={ipQuery}
                    onChange={(e) => setIpQuery(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && lookupIp()}
                  />
                  <button style={s.btn()} onClick={lookupIp} disabled={ipLoading}>
                    {ipLoading ? "..." : "Проверить"}
                  </button>
                </div>
                {ipResult?.error && (
                  <div style={{ color: "#f87171", fontSize: 12, marginTop: 8 }}>Ошибка: {ipResult.error}</div>
                )}
                {ipResult && !ipResult.error && <GeoResult result={ipResult} />}
                <div style={{ marginTop: 10, fontSize: 11, color: "#334155" }}>
                  Примеры: 185.220.101.47 (Tor), 193.56.28.103 (C2), 8.8.8.8
                </div>
              </div>

              <div style={{ flex: "1 1 300px" }}>
                <div style={s.sectionTitle}>Проверка домена</div>
                <div style={s.lookupRow}>
                  <input
                    style={s.input}
                    placeholder="Введите домен..."
                    value={domainQuery}
                    onChange={(e) => setDomainQuery(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && lookupDomain()}
                  />
                  <button style={s.btn()} onClick={lookupDomain} disabled={domainLoading}>
                    {domainLoading ? "..." : "Проверить"}
                  </button>
                </div>
                {domainResult?.error && (
                  <div style={{ color: "#f87171", fontSize: 12, marginTop: 8 }}>Ошибка: {domainResult.error}</div>
                )}
                {domainResult && !domainResult.error && <DomainResult result={domainResult} />}
                <div style={{ marginTop: 10, fontSize: 11, color: "#334155" }}>
                  Примеры: coinhive.com (майнер), xkcd.com (чистый), a1b2c3d4e5f6.com (DGA)
                </div>
              </div>
            </div>
          )}

          {tab === "beaconing" && (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <div style={s.sectionTitle}>Детектор C2 маяков (beaconing)</div>
                <button style={{ ...s.btn(), marginLeft: "auto" }} onClick={loadBeaconing} disabled={beaconLoading}>
                  {beaconLoading ? "Анализ..." : "Запустить анализ"}
                </button>
              </div>
              <div style={{ marginBottom: 12, padding: 12, background: "#0a0e18", borderRadius: 8, fontSize: 12, color: "#64748b" }}>
                Алгоритм анализирует регулярность соединений к внешним IP. Коэффициент вариации (CV) &lt; 0.20 означает машинообразный ритм — признак C2 трояна.
              </div>
              {beaconing === null ? (
                <div style={{ color: "#475569", textAlign: "center", padding: 30 }}>Нажмите «Запустить анализ»</div>
              ) : (
                <BeaconingTable data={beaconing} />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
