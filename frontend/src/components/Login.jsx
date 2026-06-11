import React, { useState } from "react";
import { api, auth } from "../api/client";

const s = {
  page: {
    minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center",
    background: "#0f1117", padding: 20,
  },
  card: {
    width: "100%", maxWidth: 380, background: "#0d111c",
    border: "1px solid #1e2a45", borderRadius: 16, padding: "36px 32px",
  },
  logo: { textAlign: "center", marginBottom: 28 },
  shield: { fontSize: 44, marginBottom: 10 },
  title: { fontSize: 20, fontWeight: 800, color: "#60a5fa", letterSpacing: 1 },
  sub: { fontSize: 12, color: "#475569", marginTop: 4 },
  label: { fontSize: 12, color: "#94a3b8", marginBottom: 6, display: "block" },
  input: {
    width: "100%", padding: "12px 14px", borderRadius: 8,
    border: "1px solid #334155", background: "#1e293b",
    color: "#e2e8f0", fontSize: 15, marginBottom: 14,
  },
  btn: (busy) => ({
    width: "100%", padding: "12px 14px", borderRadius: 8, border: "none",
    background: busy ? "#1e3a5f" : "#2563eb", color: "#fff",
    fontSize: 15, fontWeight: 700, cursor: busy ? "default" : "pointer",
  }),
  error: {
    background: "#450a0a", border: "1px solid #7f1d1d", color: "#f87171",
    borderRadius: 8, padding: "10px 14px", fontSize: 13, marginBottom: 14,
  },
  note: { fontSize: 11, color: "#334155", textAlign: "center", marginTop: 18, lineHeight: 1.6 },
};

export default function Login({ onLogin }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true); setError("");
    try {
      const res = await api.login(password);
      auth.setToken(res.token);
      onLogin();
    } catch (err) {
      setError(err.message === "HTTP 401" ? "Неверный пароль" : err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={s.page}>
      <form style={s.card} onSubmit={submit}>
        <div style={s.logo}>
          <div style={s.shield}>🛡</div>
          <div style={s.title}>FAMILY SECURITY</div>
          <div style={s.sub}>Home Network Guardian</div>
        </div>
        {error && <div style={s.error}>{error}</div>}
        <label style={s.label}>Пароль администратора</label>
        <input
          style={s.input}
          type="password"
          autoFocus
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
        />
        <button style={s.btn(busy)} type="submit" disabled={busy}>
          {busy ? "Вход..." : "Войти"}
        </button>
        <div style={s.note}>
          Пароль задаётся переменной ADMIN_PASSWORD в .env<br />
          Все данные хранятся локально на вашем сервере
        </div>
      </form>
    </div>
  );
}
