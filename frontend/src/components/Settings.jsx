import React, { useEffect, useState } from "react";
import { api } from "../api/client";

const LABELS = {
  retention_days: "Хранить логи (дней)",
  scan_interval_seconds: "Интервал сканирования (сек)",
  dns_capture_enabled: "DNS-захват (требует root)",
  network_interface: "Сетевой интерфейс",
  local_subnet: "Локальная подсеть",
};

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 24, color: "#f1f5f9" },
  section: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "20px 24px", marginBottom: 20, maxWidth: 560 },
  sTitle: { fontSize: 15, fontWeight: 600, color: "#f1f5f9", marginBottom: 16 },
  row: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #1e2535" },
  label: { fontSize: 13, color: "#94a3b8" },
  input: { background: "#0f1117", border: "1px solid #1e2535", borderRadius: 6, color: "#e2e8f0", padding: "5px 10px", fontSize: 13, width: 150 },
  saveBtn: { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "5px 14px", cursor: "pointer", fontSize: 13 },
  dangerBtn: { background: "#7f1d1d", color: "#fca5a5", border: "1px solid #991b1b", borderRadius: 8, padding: "10px 20px", cursor: "pointer", fontSize: 13, fontWeight: 600 },
  note: { fontSize: 12, color: "#64748b", marginTop: 6 },
  msg: { background: "#1e3a5f", color: "#93c5fd", borderRadius: 8, padding: "10px 16px", marginBottom: 16, fontSize: 13 },
};

export default function Settings() {
  const [settings, setSettings] = useState([]);
  const [edited, setEdited] = useState({});
  const [msg, setMsg] = useState("");

  useEffect(() => { api.settings().then(setSettings).catch(console.error); }, []);

  const flash = (m) => { setMsg(m); setTimeout(() => setMsg(""), 3000); };

  const save = async (key) => {
    if (edited[key] === undefined) return;
    await api.updateSetting(key, edited[key]);
    flash("Сохранено");
    api.settings().then(setSettings);
  };

  const clearLogs = async () => {
    if (!window.confirm("Удалить все DNS-логи и события?")) return;
    await api.clearLogs();
    flash("Логи очищены");
  };

  const applyRetention = async () => {
    const res = await api.applyRetention();
    flash(`Удалено: ${res.deleted_dns} DNS, ${res.deleted_alerts} событий`);
  };

  return (
    <div>
      <h1 style={s.h1}>Настройки</h1>
      {msg && <div style={s.msg}>{msg}</div>}

      <div style={s.section}>
        <div style={s.sTitle}>Параметры</div>
        {settings.map((st) => (
          <div key={st.key} style={s.row}>
            <span style={s.label}>{LABELS[st.key] || st.key}</span>
            <div style={{ display: "flex", gap: 8 }}>
              <input style={s.input} value={edited[st.key] ?? st.value}
                onChange={(e) => setEdited((x) => ({ ...x, [st.key]: e.target.value }))} />
              <button style={s.saveBtn} onClick={() => save(st.key)}>Сохранить</button>
            </div>
          </div>
        ))}
      </div>

      <div style={s.section}>
        <div style={s.sTitle}>Конфиденциальность</div>
        <p style={{ ...s.note, marginBottom: 14 }}>
          Все данные хранятся локально. Пароли, содержимое сообщений и URL не собираются никогда.
        </p>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <button style={s.dangerBtn} onClick={clearLogs}>🗑 Очистить все логи</button>
          <button style={{ ...s.dangerBtn, background: "#1e3a5f", color: "#93c5fd", borderColor: "#1e40af" }} onClick={applyRetention}>
            🧹 Применить retention
          </button>
        </div>
        <p style={{ ...s.note, marginTop: 10 }}>Retention удалит записи старше указанного числа дней.</p>
      </div>

      <div style={s.section}>
        <div style={s.sTitle}>О системе</div>
        <p style={s.note}>FAMILY SECURITY v2.0 — локальная система мониторинга домашней сети.</p>
        <p style={s.note}>Многолокационный режим: агенты подключаются к хабу через API-ключи.</p>
        <p style={s.note}>Real-time события: WebSocket-подключение (⚡ Live Feed).</p>
        <p style={s.note}>Без облака, без внешних API, без сбора приватных данных.</p>
      </div>
    </div>
  );
}
