import React, { useState, useEffect, useRef, useCallback } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const COLORS = {
  device: "#3b82f6",
  router: "#10b981",
  external: "#64748b",
  threat: "#ef4444",
  tor: "#a855f7",
  new: "#f59e0b",
  edge: "#334155",
  edgeThreat: "#ef4444",
};

function runForce(nodes, edges, iterations = 120) {
  const W = 900, H = 620;
  const k = Math.sqrt((W * H) / Math.max(nodes.length, 1)) * 0.7;

  const pos = nodes.map((n, i) => ({
    id: n.id,
    x: W / 2 + (Math.random() - 0.5) * W * 0.7,
    y: H / 2 + (Math.random() - 0.5) * H * 0.7,
    vx: 0, vy: 0,
  }));
  const idx = Object.fromEntries(pos.map((p, i) => [p.id, i]));

  for (let iter = 0; iter < iterations; iter++) {
    const t = 0.85 * (1 - iter / iterations);

    // Repulsion
    for (let i = 0; i < pos.length; i++) {
      for (let j = i + 1; j < pos.length; j++) {
        const dx = pos[j].x - pos[i].x || 0.01;
        const dy = pos[j].y - pos[i].y || 0.01;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (k * k) / d;
        pos[i].vx -= (dx / d) * f;
        pos[i].vy -= (dy / d) * f;
        pos[j].vx += (dx / d) * f;
        pos[j].vy += (dy / d) * f;
      }
    }

    // Attraction
    for (const e of edges) {
      const si = idx[e.source], ti = idx[e.target];
      if (si == null || ti == null) continue;
      const dx = pos[ti].x - pos[si].x;
      const dy = pos[ti].y - pos[si].y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d * d) / k;
      pos[si].vx += (dx / d) * f * 0.05;
      pos[si].vy += (dy / d) * f * 0.05;
      pos[ti].vx -= (dx / d) * f * 0.05;
      pos[ti].vy -= (dy / d) * f * 0.05;
    }

    // Center gravity
    for (const p of pos) {
      p.vx += ((W / 2 - p.x) / W) * 2;
      p.vy += ((H / 2 - p.y) / H) * 2;
      p.x = Math.max(40, Math.min(W - 40, p.x + p.vx * t));
      p.y = Math.max(40, Math.min(H - 40, p.y + p.vy * t));
      p.vx *= 0.5; p.vy *= 0.5;
    }
  }
  return Object.fromEntries(pos.map((p) => [p.id, { x: p.x, y: p.y }]));
}

function nodeColor(n) {
  if (n.is_threat) return COLORS.threat;
  if (n.is_tor) return COLORS.tor;
  if (n.is_new) return COLORS.new;
  if (n.type === "external") return COLORS.external;
  const dt = (n.os_hint || "").toLowerCase();
  if (dt.includes("router") || n.label?.toLowerCase().includes("роутер")) return COLORS.router;
  return COLORS.device;
}

function nodeRadius(n) {
  if (n.type === "external" || n.type === "external_threat") return 9;
  const dt = (n.os_hint || "").toLowerCase();
  if (dt.includes("router")) return 14;
  return 11;
}

export default function NetworkMap() {
  const { selectedLocationId } = useApp();
  const [data, setData] = useState(null);
  const [positions, setPositions] = useState({});
  const [hovered, setHovered] = useState(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const svgRef = useRef();
  const dragging = useRef(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const params = selectedLocationId ? `?location_id=${selectedLocationId}` : "";
      const d = await api.networkTopology(params);
      setData(d);
      setPositions(runForce(d.nodes, d.edges));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedLocationId]);

  useEffect(() => { load(); }, [load]);

  const onWheel = (e) => {
    e.preventDefault();
    setZoom((z) => Math.max(0.4, Math.min(3, z - e.deltaY * 0.001)));
  };

  const onMouseDown = (e) => {
    if (e.target === svgRef.current || e.target.tagName === "svg") {
      dragging.current = { type: "pan", x: e.clientX - pan.x, y: e.clientY - pan.y };
    }
  };

  const onMouseMove = (e) => {
    if (!dragging.current) return;
    if (dragging.current.type === "pan") {
      setPan({ x: e.clientX - dragging.current.x, y: e.clientY - dragging.current.y });
    }
  };

  const onMouseUp = () => { dragging.current = null; };

  const s = {
    container: { background: "#0d111c", borderRadius: 12, border: "1px solid #1e2a45", overflow: "hidden" },
    header: { display: "flex", alignItems: "center", gap: 12, padding: "14px 18px", borderBottom: "1px solid #1e2a45" },
    title: { fontSize: 16, fontWeight: 700, color: "#e2e8f0" },
    controls: { marginLeft: "auto", display: "flex", gap: 8 },
    btn: {
      padding: "5px 12px", borderRadius: 6, border: "1px solid #334155",
      background: "#1e293b", color: "#94a3b8", cursor: "pointer", fontSize: 12,
    },
    legend: { display: "flex", gap: 14, padding: "8px 18px", borderBottom: "1px solid #1a2035", flexWrap: "wrap" },
    legendItem: { display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: "#64748b" },
    dot: (c) => ({ width: 8, height: 8, borderRadius: "50%", background: c }),
    tooltip: {
      position: "absolute", background: "#1e2a45", border: "1px solid #334155",
      borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "#e2e8f0",
      pointerEvents: "none", maxWidth: 220, zIndex: 10,
    },
    empty: { padding: 60, textAlign: "center", color: "#475569", fontSize: 14 },
    error: { padding: 40, textAlign: "center", color: "#ef4444", fontSize: 14 },
  };

  if (loading) return (
    <div style={s.container}>
      <div style={{ ...s.empty }}>Построение карты сети...</div>
    </div>
  );

  if (error) return (
    <div style={s.container}>
      <div style={s.error}>Ошибка загрузки: {error}</div>
    </div>
  );

  if (!data || data.nodes.length === 0) return (
    <div style={s.container}>
      <div style={s.empty}>Нет данных о топологии сети</div>
    </div>
  );

  const threatEdges = data.edges.filter((e) => e.is_threat).length;
  const threatNodes = data.nodes.filter((n) => n.is_threat || n.is_tor).length;

  return (
    <div style={s.container}>
      <div style={s.header}>
        <span style={s.title}>🗺 Карта сети</span>
        <span style={{ fontSize: 12, color: "#64748b" }}>
          {data.nodes.length} узлов · {data.edges.length} соединений
          {threatNodes > 0 && <span style={{ color: "#ef4444", marginLeft: 8 }}>⚠ {threatNodes} угроз</span>}
        </span>
        <div style={s.controls}>
          <button style={s.btn} onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}>Сброс</button>
          <button style={s.btn} onClick={load}>Обновить</button>
        </div>
      </div>
      <div style={s.legend}>
        {[
          ["Устройство", COLORS.device],
          ["Роутер", COLORS.router],
          ["Внешний IP", COLORS.external],
          ["Угроза", COLORS.threat],
          ["Tor", COLORS.tor],
          ["Новое", COLORS.new],
        ].map(([label, color]) => (
          <div key={label} style={s.legendItem}>
            <div style={s.dot(color)} />
            <span>{label}</span>
          </div>
        ))}
        <div style={{ ...s.legendItem, marginLeft: "auto" }}>
          <span style={{ color: "#ef4444" }}>━</span> Угрозы&nbsp;&nbsp;
          <span style={{ color: COLORS.edge }}>━</span> Норма
        </div>
      </div>

      <div style={{ position: "relative" }} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp}>
        <svg
          ref={svgRef}
          width="100%" height={500}
          style={{ cursor: dragging.current ? "grabbing" : "grab", display: "block" }}
          onWheel={onWheel}
          onMouseDown={onMouseDown}
        >
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {data.edges.map((e, i) => {
              const sp = positions[e.source];
              const tp = positions[e.target];
              if (!sp || !tp) return null;
              return (
                <line
                  key={i}
                  x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y}
                  stroke={e.is_threat ? COLORS.edgeThreat : COLORS.edge}
                  strokeWidth={e.is_threat ? 1.8 : 1}
                  strokeOpacity={e.is_threat ? 0.8 : 0.4}
                  strokeDasharray={e.is_threat ? "4 2" : undefined}
                />
              );
            })}
            {/* Nodes */}
            {data.nodes.map((n) => {
              const p = positions[n.id];
              if (!p) return null;
              const r = nodeRadius(n);
              const color = nodeColor(n);
              const isHovered = hovered?.id === n.id;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHovered(n)}
                  onMouseLeave={() => setHovered(null)}
                >
                  {isHovered && (
                    <circle r={r + 6} fill={color} fillOpacity={0.2} />
                  )}
                  <circle
                    r={r}
                    fill={color}
                    fillOpacity={0.9}
                    stroke={isHovered ? "#fff" : color}
                    strokeWidth={isHovered ? 2 : 1}
                  />
                  {n.is_threat && (
                    <text y={-r - 3} textAnchor="middle" fontSize={9} fill="#ef4444">⚠</text>
                  )}
                  <text
                    y={r + 12}
                    textAnchor="middle"
                    fontSize={9}
                    fill="#94a3b8"
                    style={{ userSelect: "none" }}
                  >
                    {(n.label || n.ip || "").slice(0, 16)}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {hovered && (() => {
          const p = positions[hovered.id];
          if (!p) return null;
          const sx = p.x * zoom + pan.x;
          const sy = p.y * zoom + pan.y;
          return (
            <div style={{ ...s.tooltip, left: Math.min(sx + 16, window.innerWidth - 240), top: sy - 10 }}>
              <div style={{ fontWeight: 700, marginBottom: 4, color: nodeColor(hovered) }}>
                {hovered.label || hovered.ip}
              </div>
              {hovered.ip && <div>IP: <span style={{ color: "#94a3b8" }}>{hovered.ip}</span></div>}
              {hovered.mac && <div>MAC: <span style={{ color: "#94a3b8" }}>{hovered.mac}</span></div>}
              {hovered.vendor && <div>Производитель: <span style={{ color: "#94a3b8" }}>{hovered.vendor}</span></div>}
              {hovered.os_hint && <div>ОС: <span style={{ color: "#94a3b8" }}>{hovered.os_hint}</span></div>}
              {hovered.country && (
                <div>Страна: <span style={{ color: "#94a3b8" }}>{hovered.country}</span></div>
              )}
              {hovered.org && <div>Орг: <span style={{ color: "#94a3b8" }}>{hovered.org}</span></div>}
              {hovered.is_threat && (
                <div style={{ color: "#ef4444", marginTop: 4, fontWeight: 600 }}>⚠ Угроза</div>
              )}
              {hovered.is_tor && (
                <div style={{ color: "#a855f7", marginTop: 4, fontWeight: 600 }}>Tor exit node</div>
              )}
              {hovered.is_new && (
                <div style={{ color: "#f59e0b", marginTop: 4 }}>Новое устройство</div>
              )}
            </div>
          );
        })()}
      </div>

      <div style={{ padding: "8px 18px 12px", borderTop: "1px solid #1a2035", fontSize: 11, color: "#334155" }}>
        Прокрутка — масштаб · Перетащите фон — панорама · Наведите — детали
      </div>
    </div>
  );
}
