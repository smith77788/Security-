import React from "react";
import { BrowserRouter, Routes, Route, NavLink, useLocation } from "react-router-dom";
import Overview from "./components/Overview";
import Devices from "./components/Devices";
import DNSActivity from "./components/DNSActivity";
import Alerts from "./components/Alerts";
import Assistant from "./components/Assistant";
import Settings from "./components/Settings";

const NAV = [
  { path: "/", label: "Обзор", icon: "🏠" },
  { path: "/devices", label: "Устройства", icon: "📡" },
  { path: "/dns", label: "DNS", icon: "🌐" },
  { path: "/alerts", label: "События", icon: "🔔" },
  { path: "/assistant", label: "Помощник", icon: "💬" },
  { path: "/settings", label: "Настройки", icon: "⚙️" },
];

const s = {
  layout: { display: "flex", minHeight: "100vh" },
  sidebar: {
    width: 220, background: "#161b27", padding: "24px 0",
    display: "flex", flexDirection: "column", flexShrink: 0,
    borderRight: "1px solid #1e2535",
  },
  logo: { padding: "0 20px 24px", borderBottom: "1px solid #1e2535" },
  logoTitle: { fontSize: 18, fontWeight: 700, color: "#60a5fa", letterSpacing: 1 },
  logoSub: { fontSize: 11, color: "#64748b", marginTop: 2 },
  nav: { padding: "16px 0", flex: 1 },
  link: {
    display: "flex", alignItems: "center", gap: 10,
    padding: "10px 20px", color: "#94a3b8", textDecoration: "none",
    fontSize: 14, transition: "all .15s",
  },
  main: { flex: 1, padding: "28px 32px", overflow: "auto", background: "#0f1117" },
};

function Sidebar() {
  return (
    <aside style={s.sidebar}>
      <div style={s.logo}>
        <div style={s.logoTitle}>FAMILY SECURITY</div>
        <div style={s.logoSub}>Home Network Guardian</div>
      </div>
      <nav style={s.nav}>
        {NAV.map(({ path, label, icon }) => (
          <NavLink
            key={path}
            to={path}
            end={path === "/"}
            style={({ isActive }) => ({
              ...s.link,
              ...(isActive ? { color: "#60a5fa", background: "#1e2535", borderLeft: "3px solid #60a5fa" } : {}),
            })}
          >
            <span>{icon}</span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div style={s.layout}>
        <Sidebar />
        <main style={s.main}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/dns" element={<DNSActivity />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/assistant" element={<Assistant />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
