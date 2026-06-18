import React, { useState } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const ICONS = ["🏠","🏢","🌲","🏖","🏔","🏡","🏗","🌇","🏙","🏘"];
const COLORS = ["#3b82f6","#22c55e","#a855f7","#f97316","#ec4899","#14b8a6","#eab308","#ef4444"];

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 22, color: "#f1f5f9" },
  grid: { display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 16, marginBottom: 28 },
  card: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "20px 22px" },
  cardHeader: { display: "flex", alignItems: "center", gap: 12, marginBottom: 14 },
  icon: { fontSize: 32 },
  name: { fontSize: 16, fontWeight: 700, color: "#f1f5f9" },
  sub: { fontSize: 12, color: "#64748b", marginTop: 2 },
  keyBox: { background: "#0f1117", borderRadius: 6, padding: "8px 10px", fontFamily: "monospace", fontSize: 11, color: "#94a3b8", wordBreak: "break-all", marginBottom: 10 },
  row: { display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 },
  btn: (variant) => ({
    padding: "5px 12px", borderRadius: 6, border: "1px solid #1e2535", cursor: "pointer", fontSize: 12,
    background: variant === "danger" ? "#450a0a" : variant === "primary" ? "#1d4ed8" : "#161b27",
    color: variant === "danger" ? "#fca5a5" : variant === "primary" ? "#fff" : "#94a3b8",
  }),
  dot: (on) => ({ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: on ? "#22c55e" : "#475569", marginRight: 6 }),
  addCard: { background: "#0f1117", border: "2px dashed #1e2535", borderRadius: 12, padding: "24px", display: "flex", flexDirection: "column", gap: 12 },
  label: { fontSize: 12, color: "#64748b", marginBottom: 4 },
  input: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 6, color: "#e2e8f0", padding: "7px 10px", fontSize: 13, width: "100%" },
  iconGrid: { display: "flex", gap: 6, flexWrap: "wrap" },
  iconBtn: (sel) => ({ fontSize: 22, background: sel ? "#1e2a45" : "transparent", border: sel ? "1px solid #3b82f6" : "1px solid transparent", borderRadius: 6, cursor: "pointer", padding: "4px 6px" }),
  colorDot: (sel, c) => ({ width: 22, height: 22, borderRadius: "50%", background: c, cursor: "pointer", border: sel ? "3px solid #fff" : "3px solid transparent", flexShrink: 0 }),
};

function AddLocationForm({ onDone }) {
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [icon, setIcon] = useState("🏠");
  const [color, setColor] = useState("#3b82f6");
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await api.createLocation({ name: name.trim(), address: address.trim() || null, icon, color });
      onDone();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={s.addCard}>
      <div style={{ fontSize: 15, fontWeight: 600, color: "#f1f5f9" }}>Добавить локацию</div>
      <div>
        <div style={s.label}>Название *</div>
        <input style={s.input} value={name} onChange={(e) => setName(e.target.value)} placeholder="Дом, Дача, Квартира…" />
      </div>
      <div>
        <div style={s.label}>Адрес</div>
        <input style={s.input} value={address} onChange={(e) => setAddress(e.target.value)} placeholder="необязательно" />
      </div>
      <div>
        <div style={s.label}>Иконка</div>
        <div style={s.iconGrid}>{ICONS.map((ic) => <button key={ic} style={s.iconBtn(icon === ic)} onClick={() => setIcon(ic)}>{ic}</button>)}</div>
      </div>
      <div>
        <div style={s.label}>Цвет</div>
        <div style={{ display: "flex", gap: 8 }}>{COLORS.map((c) => <div key={c} style={s.colorDot(color === c, c)} onClick={() => setColor(c)} />)}</div>
      </div>
      <button style={s.btn("primary")} onClick={save} disabled={saving}>{saving ? "Сохранение…" : "Создать"}</button>
    </div>
  );
}

function LocationCard({ loc, onRefresh }) {
  const [showKey, setShowKey] = useState(false);
  const [rotating, setRotating] = useState(false);
  const hb = loc.last_heartbeat ? new Date(loc.last_heartbeat).toLocaleString("ru") : "никогда";

  const rotate = async () => {
    if (!window.confirm("Сгенерировать новый API-ключ? Агент на этой локации нужно будет перезапустить.")) return;
    setRotating(true);
    await api.rotateKey(loc.id);
    onRefresh();
    setRotating(false);
  };

  const del = async () => {
    if (!window.confirm(`Удалить локацию «${loc.name}»? Все данные будут потеряны.`)) return;
    await api.deleteLocation(loc.id);
    onRefresh();
  };

  return (
    <div style={{ ...s.card, borderColor: loc.color + "44" }}>
      <div style={s.cardHeader}>
        <span style={s.icon}>{loc.icon}</span>
        <div style={{ flex: 1 }}>
          <div style={s.name}><span style={s.dot(loc.is_online)} />{loc.name}</div>
          <div style={s.sub}>{loc.address || "Адрес не указан"}</div>
          <div style={{ fontSize: 11, color: "#475569", marginTop: 2 }}>
            {loc.is_online ? "● Онлайн" : "○ Оффлайн"} · Последний раз: {hb}
          </div>
        </div>
      </div>

      <div style={s.label}>API-ключ для агента</div>
      {showKey ? (
        <div style={s.keyBox}>{loc.api_key}</div>
      ) : (
        <div style={{ ...s.keyBox, cursor: "pointer", color: "#475569" }} onClick={() => setShowKey(true)}>
          •••••••••••••• (нажмите, чтобы показать)
        </div>
      )}

      <div style={s.row}>
        <button style={s.btn()} onClick={() => setShowKey((v) => !v)}>{showKey ? "Скрыть" : "Показать ключ"}</button>
        <button style={s.btn()} onClick={rotate} disabled={rotating}>{rotating ? "…" : "Сменить ключ"}</button>
        <button style={s.btn("danger")} onClick={del}>Удалить</button>
      </div>
    </div>
  );
}

export default function Locations() {
  const { locations, refreshLocations } = useApp();

  const handleDone = () => refreshLocations();

  return (
    <div>
      <h1 style={s.h1}>Локации</h1>
      <p style={{ color: "#64748b", fontSize: 13, marginBottom: 20 }}>
        Каждая локация — отдельная сеть (дом, дача, квартира). Агент на каждом устройстве подключается к хабу по API-ключу.
      </p>
      <div style={s.grid}>
        {locations.map((loc) => (
          <LocationCard key={loc.id} loc={loc} onRefresh={handleDone} />
        ))}
        <AddLocationForm onDone={handleDone} />
      </div>

      <div style={{ background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "18px 22px", maxWidth: 600 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "#f1f5f9", marginBottom: 10 }}>Как подключить агент</div>
        <ol style={{ color: "#94a3b8", fontSize: 13, lineHeight: 2, paddingLeft: 20 }}>
          <li>Создайте локацию здесь и скопируйте API-ключ</li>
          <li>На Raspberry Pi / мини-ПК удалённой локации склонируйте репозиторий</li>
          <li>Создайте <code style={{ color: "#60a5fa" }}>agent/.env</code> из примера <code style={{ color: "#60a5fa" }}>agent/.env.example</code></li>
          <li>Укажите <code style={{ color: "#60a5fa" }}>HUB_URL</code> (IP хаба через VPN) и <code style={{ color: "#60a5fa" }}>API_KEY</code></li>
          <li>Запустите: <code style={{ color: "#60a5fa" }}>docker compose -f docker-compose.agent.yml up -d</code></li>
          <li>Статус локации станет «Онлайн» в течение 30 секунд</li>
        </ol>
        <div style={{ marginTop: 10, fontSize: 12, color: "#475569" }}>
          💡 Для связи через интернет рекомендуется WireGuard VPN или Tailscale между устройствами.
        </div>
      </div>
    </div>
  );
}
