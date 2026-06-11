import React, { useEffect, useState } from "react";
import { api } from "../api/client";

const GENERAL_KEYS = [
  "retention_days", "scan_interval_seconds", "dns_capture_enabled",
  "network_interface", "local_subnet",
];
const TELEGRAM_KEYS = ["telegram_bot_token", "telegram_chat_id"];
const TOGGLE_KEYS = ["notify_on_critical", "notify_on_warning", "notify_on_new_device"];

const LABELS = {
  retention_days: "Хранить логи (дней)",
  scan_interval_seconds: "Интервал сканирования (сек)",
  dns_capture_enabled: "DNS-захват (требует root)",
  network_interface: "Сетевой интерфейс",
  local_subnet: "Локальная подсеть",
  telegram_bot_token: "Токен бота (@BotFather)",
  telegram_chat_id: "Chat ID (@userinfobot)",
  notify_on_critical: "Критические события",
  notify_on_warning: "Предупреждения",
  notify_on_new_device: "Новые устройства",
};

const s = {
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 24, color: "#f1f5f9" },
  section: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 12, padding: "20px 24px", marginBottom: 20, maxWidth: 560 },
  sTitle: { fontSize: 15, fontWeight: 600, color: "#f1f5f9", marginBottom: 16 },
  row: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #1e2535", gap: 10, flexWrap: "wrap" },
  label: { fontSize: 13, color: "#94a3b8" },
  input: { background: "#0f1117", border: "1px solid #1e2535", borderRadius: 6, color: "#e2e8f0", padding: "5px 10px", fontSize: 13, width: 170 },
  saveBtn: { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "5px 14px", cursor: "pointer", fontSize: 13 },
  dangerBtn: { background: "#7f1d1d", color: "#fca5a5", border: "1px solid #991b1b", borderRadius: 8, padding: "10px 20px", cursor: "pointer", fontSize: 13, fontWeight: 600 },
  note: { fontSize: 12, color: "#64748b", marginTop: 6, lineHeight: 1.6 },
  msg: (err) => ({
    background: err ? "#450a0a" : "#1e3a5f", color: err ? "#f87171" : "#93c5fd",
    borderRadius: 8, padding: "10px 16px", marginBottom: 16, fontSize: 13,
  }),
  toggle: (on) => ({
    width: 40, height: 22, borderRadius: 11, position: "relative", cursor: "pointer",
    background: on ? "#2563eb" : "#1e2535", border: "none", transition: "background .15s",
    flexShrink: 0,
  }),
  knob: (on) => ({
    position: "absolute", top: 2, left: on ? 20 : 2, width: 18, height: 18,
    borderRadius: "50%", background: "#e2e8f0", transition: "left .15s",
  }),
};

function Toggle({ on, onChange }) {
  return (
    <button style={s.toggle(on)} onClick={onChange} type="button">
      <span style={s.knob(on)} />
    </button>
  );
}

export default function Settings() {
  const [settings, setSettings] = useState([]);
  const [edited, setEdited] = useState({});
  const [msg, setMsg] = useState("");
  const [msgErr, setMsgErr] = useState(false);
  const [testing, setTesting] = useState(false);

  const reload = () => api.settings().then(setSettings).catch(console.error);
  useEffect(() => { reload(); }, []);

  const flash = (m, err = false) => {
    setMsg(m); setMsgErr(err);
    setTimeout(() => setMsg(""), 4000);
  };

  const valueOf = (key) => {
    const st = settings.find((x) => x.key === key);
    return edited[key] ?? st?.value ?? "";
  };

  const save = async (key) => {
    if (edited[key] === undefined) return;
    await api.updateSetting(key, edited[key]);
    flash("Сохранено");
    reload();
  };

  const toggleSetting = async (key) => {
    const newVal = valueOf(key) === "true" ? "false" : "true";
    await api.updateSetting(key, newVal);
    reload();
  };

  const testTelegram = async () => {
    // Persist any unsaved edits first so the test uses current values
    setTesting(true);
    try {
      for (const key of TELEGRAM_KEYS) {
        if (edited[key] !== undefined) await api.updateSetting(key, edited[key]);
      }
      await api.testTelegram();
      flash("✅ Тестовое сообщение отправлено — проверьте Telegram");
      reload();
    } catch (e) {
      flash(`Ошибка: ${e.message}`, true);
    } finally {
      setTesting(false);
    }
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

  const renderInputRow = (key, secret = false) => (
    <div key={key} style={s.row}>
      <span style={s.label}>{LABELS[key] || key}</span>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          style={s.input}
          type={secret ? "password" : "text"}
          value={valueOf(key)}
          onChange={(e) => setEdited((x) => ({ ...x, [key]: e.target.value }))}
        />
        <button style={s.saveBtn} onClick={() => save(key)}>Сохранить</button>
      </div>
    </div>
  );

  return (
    <div>
      <h1 style={s.h1}>Настройки</h1>
      {msg && <div style={s.msg(msgErr)}>{msg}</div>}

      <div style={s.section}>
        <div style={s.sTitle}>Параметры</div>
        {GENERAL_KEYS.map((key) => renderInputRow(key))}
      </div>

      <div style={s.section}>
        <div style={s.sTitle}>📲 Уведомления в Telegram</div>
        {TELEGRAM_KEYS.map((key) => renderInputRow(key, key === "telegram_bot_token"))}
        {TOGGLE_KEYS.map((key) => (
          <div key={key} style={s.row}>
            <span style={s.label}>{LABELS[key]}</span>
            <Toggle on={valueOf(key) === "true"} onChange={() => toggleSetting(key)} />
          </div>
        ))}
        <div style={{ marginTop: 14 }}>
          <button
            style={{ ...s.saveBtn, background: "#0f766e", opacity: testing ? 0.6 : 1 }}
            onClick={testTelegram}
            disabled={testing}
          >
            {testing ? "Отправка..." : "📨 Отправить тест"}
          </button>
        </div>
        <p style={s.note}>
          1. Создайте бота через @BotFather → получите токен.<br />
          2. Узнайте свой chat ID через @userinfobot.<br />
          3. Напишите боту /start (иначе он не сможет писать вам первым).
        </p>
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
        <p style={s.note}>FAMILY SECURITY v3.1 — локальная система мониторинга домашней сети.</p>
        <p style={s.note}>Вход по JWT-токену, Telegram-уведомления, блокировка устройств.</p>
        <p style={s.note}>Многолокационный режим: агенты подключаются к хабу через API-ключи.</p>
        <p style={s.note}>📱 Установите на телефон: откройте в браузере → «Добавить на главный экран».</p>
        <p style={s.note}>Без облака, без внешних API, без сбора приватных данных.</p>
      </div>
    </div>
  );
}
