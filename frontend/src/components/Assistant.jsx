import React, { useState, useRef, useEffect } from "react";
import { api } from "../api/client";
import { useApp } from "../context/AppContext";

const SUGGESTIONS = [
  "Почему интернет медленный?",
  "Есть ли новые устройства?",
  "Что было подозрительного сегодня?",
  "Какие устройства самые активные?",
  "Какие домены чаще всего запрашиваются?",
  "Сколько устройств в сети?",
];

const s = {
  page: { maxWidth: 720 },
  h1: { fontSize: 22, fontWeight: 700, marginBottom: 8, color: "#f1f5f9" },
  sub: { fontSize: 13, color: "#64748b", marginBottom: 20 },
  locNote: { background: "#131c30", border: "1px solid #1e2535", borderRadius: 8, padding: "8px 12px", fontSize: 12, color: "#60a5fa", marginBottom: 18 },
  suggestions: { display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 22 },
  suggBtn: { background: "#161b27", border: "1px solid #1e2535", borderRadius: 20, color: "#94a3b8", padding: "6px 14px", fontSize: 13, cursor: "pointer" },
  chat: { display: "flex", flexDirection: "column", gap: 14, marginBottom: 20, minHeight: 100 },
  bubble: (role) => ({
    maxWidth: "80%", padding: "12px 16px", borderRadius: 12, fontSize: 14, lineHeight: 1.6,
    alignSelf: role === "user" ? "flex-end" : "flex-start",
    background: role === "user" ? "#1d4ed8" : "#161b27",
    color: role === "user" ? "#fff" : "#cbd5e1",
    border: role === "user" ? "none" : "1px solid #1e2535",
    whiteSpace: "pre-wrap",
  }),
  inputRow: { display: "flex", gap: 10 },
  input: { flex: 1, background: "#161b27", border: "1px solid #1e2535", borderRadius: 8, color: "#e2e8f0", padding: "10px 14px", fontSize: 14, outline: "none" },
  sendBtn: { background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 8, padding: "10px 20px", cursor: "pointer", fontSize: 14, fontWeight: 600 },
};

export default function Assistant() {
  const { selectedLocationId, locations } = useApp();
  const [messages, setMessages] = useState([
    { role: "assistant", text: "Привет! Я локальный помощник по безопасности. Задайте вопрос о вашей домашней сети." },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);
  const locName = selectedLocationId ? locations.find((l) => l.id === selectedLocationId)?.name : null;

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const send = async (question) => {
    const q = question || input.trim();
    if (!q || loading) return;
    setInput("");
    setMessages((m) => [...m, { role: "user", text: q }]);
    setLoading(true);
    try {
      const res = await api.ask(q, selectedLocationId);
      setMessages((m) => [...m, { role: "assistant", text: res.answer }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", text: "Ошибка: " + e.message }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={s.page}>
      <h1 style={s.h1}>Помощник</h1>
      <p style={s.sub}>Задайте вопрос о сети. Всё анализируется локально, без LLM.</p>
      {locName && <div style={s.locNote}>📍 Анализирую только локацию: <strong>{locName}</strong></div>}
      <div style={s.suggestions}>
        {SUGGESTIONS.map((q) => <button key={q} style={s.suggBtn} onClick={() => send(q)}>{q}</button>)}
      </div>
      <div style={s.chat}>
        {messages.map((m, i) => <div key={i} style={s.bubble(m.role)}>{m.text}</div>)}
        {loading && <div style={s.bubble("assistant")}>…</div>}
        <div ref={bottomRef} />
      </div>
      <div style={s.inputRow}>
        <input style={s.input} value={input} onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()} placeholder="Введите вопрос…" />
        <button style={s.sendBtn} onClick={() => send()}>Спросить</button>
      </div>
    </div>
  );
}
