import React, { useState, useEffect, useCallback } from "react";
import { BrowserRouter, Routes, Route, NavLink, useLocation } from "react-router-dom";
import { AppProvider, useApp } from "./context/AppContext";
import { useWebSocket } from "./hooks/useWebSocket";
import { useIsMobile } from "./hooks/useIsMobile";
import { api, auth } from "./api/client";
import Login from "./components/Login";
import Overview from "./components/Overview";
import Devices from "./components/Devices";
import DNSActivity from "./components/DNSActivity";
import Alerts from "./components/Alerts";
import Assistant from "./components/Assistant";
import Settings from "./components/Settings";
import Locations from "./components/Locations";
import RealtimeFeed from "./components/RealtimeFeed";
import NetworkMap from "./components/NetworkMap";
import Connections from "./components/Connections";
import Bandwidth from "./components/Bandwidth";
import ThreatIntel from "./components/ThreatIntel";

const NAV = [
  { path: "/",             label: "Обзор",      icon: "🏠" },
  { path: "/locations",    label: "Локации",    icon: "📍" },
  { path: "/devices",      label: "Устройства", icon: "📡" },
  { path: "/dns",          label: "DNS",        icon: "🌐" },
  { path: "/alerts",       label: "События",    icon: "🔔" },
  { path: "/map",          label: "Карта сети", icon: "🗺" },
  { path: "/connections",  label: "Соединения", icon: "🔗" },
  { path: "/bandwidth",    label: "Трафик",     icon: "📊" },
  { path: "/threats",      label: "Угрозы",     icon: "🛡" },
  { path: "/feed",         label: "Live Feed",  icon: "⚡" },
  { path: "/assistant",    label: "Помощник",   icon: "💬" },
  { path: "/settings",     label: "Настройки",  icon: "⚙️" },
];

// Bottom tab bar on mobile shows the 4 most used pages + "Ещё" (opens drawer)
const MOBILE_TABS = ["/", "/devices", "/alerts", "/map"];

const ONLINE_DOT = { width: 7, height: 7, borderRadius: "50%", display: "inline-block", marginRight: 4 };

const s = {
  layout: { display: "flex", minHeight: "100vh" },
  sidebar: (mobile, open) => ({
    width: 232, background: "#0d111c", flexShrink: 0,
    display: "flex", flexDirection: "column",
    borderRight: "1px solid #1a2035",
    ...(mobile ? {
      position: "fixed", top: 0, bottom: 0, left: 0, zIndex: 1000,
      transform: open ? "translateX(0)" : "translateX(-100%)",
      transition: "transform .22s ease",
      boxShadow: open ? "0 0 40px rgba(0,0,0,.6)" : "none",
      overflowY: "auto",
    } : {}),
  }),
  overlay: {
    position: "fixed", inset: 0, background: "rgba(0,0,0,.5)", zIndex: 999,
  },
  logo: { padding: "20px 18px 18px", borderBottom: "1px solid #1a2035" },
  logoTitle: { fontSize: 17, fontWeight: 800, color: "#60a5fa", letterSpacing: 1 },
  logoSub: { fontSize: 11, color: "#475569", marginTop: 3 },
  locationBar: { padding: "10px 12px", borderBottom: "1px solid #1a2035" },
  locBtn: (active) => ({
    display: "flex", alignItems: "center", gap: 6, width: "100%",
    padding: "5px 8px", borderRadius: 6, border: "none", cursor: "pointer",
    background: active ? "#1e2a45" : "transparent",
    color: active ? "#e2e8f0" : "#64748b", fontSize: 12, textAlign: "left",
  }),
  nav: { padding: "10px 0", flex: 1 },
  link: {
    display: "flex", alignItems: "center", gap: 10,
    padding: "9px 18px", color: "#64748b", textDecoration: "none",
    fontSize: 13.5, transition: "all .12s",
  },
  main: (mobile) => ({
    flex: 1, overflow: "auto", background: "#0f1117",
    padding: mobile ? "16px 14px 80px" : "26px 30px",
    minWidth: 0,
  }),
  badge: {
    background: "#ef4444", color: "#fff", borderRadius: 10,
    padding: "0 5px", fontSize: 10, fontWeight: 700, minWidth: 16, textAlign: "center",
  },
  // Mobile top bar
  topbar: {
    position: "sticky", top: 0, zIndex: 100,
    display: "flex", alignItems: "center", gap: 12,
    padding: "12px 14px", background: "#0d111c",
    borderBottom: "1px solid #1a2035",
  },
  burger: {
    background: "none", border: "none", color: "#94a3b8",
    fontSize: 22, cursor: "pointer", padding: "2px 6px", lineHeight: 1,
  },
  topTitle: { fontSize: 15, fontWeight: 800, color: "#60a5fa", letterSpacing: 0.5 },
  // Mobile bottom tab bar
  tabbar: {
    position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 100,
    display: "flex", background: "#0d111c",
    borderTop: "1px solid #1a2035",
    paddingBottom: "env(safe-area-inset-bottom, 0)",
  },
  tab: (active) => ({
    flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
    gap: 2, padding: "8px 0 6px", textDecoration: "none",
    color: active ? "#60a5fa" : "#475569", fontSize: 10,
    position: "relative",
    background: "none", border: "none", cursor: "pointer",
  }),
  tabIcon: { fontSize: 19, lineHeight: 1 },
  tabBadge: {
    position: "absolute", top: 4, right: "calc(50% - 18px)",
    background: "#ef4444", color: "#fff", borderRadius: 8,
    padding: "0 4px", fontSize: 9, fontWeight: 700, minWidth: 13, textAlign: "center",
  },
  toastContainer: {
    position: "fixed", bottom: 80, right: 14, left: 14, zIndex: 9999,
    display: "flex", flexDirection: "column", gap: 8, maxWidth: 340, marginLeft: "auto",
  },
  toast: (sev) => ({
    padding: "12px 16px", borderRadius: 10, fontSize: 13,
    boxShadow: "0 4px 20px rgba(0,0,0,.4)",
    background: sev === "critical" ? "#450a0a" : sev === "warning" ? "#431407" : "#0f172a",
    border: `1px solid ${sev === "critical" ? "#7f1d1d" : sev === "warning" ? "#78350f" : "#1e2a45"}`,
    color: "#f1f5f9",
    animation: "slideIn .25s ease",
  }),
};

function ToastLayer() {
  const { toasts } = useApp();
  return (
    <div style={s.toastContainer}>
      <style>{`@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:none;opacity:1}}`}</style>
      {toasts.map((t) => {
        const sev = t.payload?.severity || (t.type === "new_device" ? "warning" : "info");
        return (
          <div key={t.id} style={s.toast(sev)}>
            <div style={{ fontWeight: 600, marginBottom: 3 }}>
              {t.type === "alert" ? "🚨" : t.type === "new_device" ? "📡" : "📍"}{" "}
              {t.location_name && <span style={{ color: "#94a3b8" }}>[{t.location_name}] </span>}
              {t.type === "alert" ? t.payload?.message : t.type === "new_device" ? `Новое устройство: ${t.payload?.vendor}` : "Статус локации изменился"}
            </div>
            {t.type === "location_status" && (
              <div style={{ fontSize: 12, color: "#94a3b8" }}>{t.payload?.online ? "Онлайн" : "Оффлайн"}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function SidebarLocationPicker() {
  const { locations, selectedLocationId, setSelectedLocationId } = useApp();
  return (
    <div style={s.locationBar}>
      <div style={{ fontSize: 10, color: "#475569", marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Локация</div>
      <button style={s.locBtn(!selectedLocationId)} onClick={() => setSelectedLocationId(null)}>
        🌍 <span>Все локации</span>
      </button>
      {locations.map((loc) => (
        <button key={loc.id} style={s.locBtn(selectedLocationId === loc.id)} onClick={() => setSelectedLocationId(loc.id)}>
          <span style={{ ...ONLINE_DOT, background: loc.is_online ? "#22c55e" : "#475569" }} />
          <span style={{ marginRight: 4 }}>{loc.icon}</span>
          <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{loc.name}</span>
          {loc.unread_alerts > 0 && <span style={s.badge}>{loc.unread_alerts}</span>}
        </button>
      ))}
    </div>
  );
}

function Sidebar({ mobile, open, onClose, onLogout, showLogout }) {
  const { unreadCount } = useApp();
  return (
    <>
      {mobile && open && <div style={s.overlay} onClick={onClose} />}
      <aside style={s.sidebar(mobile, open)}>
        <div style={s.logo}>
          <div style={s.logoTitle}>FAMILY SECURITY</div>
          <div style={s.logoSub}>Home Network Guardian</div>
        </div>
        <SidebarLocationPicker />
        <nav style={s.nav}>
          {NAV.map(({ path, label, icon }) => (
            <NavLink
              key={path}
              to={path}
              end={path === "/"}
              onClick={mobile ? onClose : undefined}
              style={({ isActive }) => ({
                ...s.link,
                ...(isActive ? { color: "#60a5fa", background: "#131c30", borderLeft: "3px solid #60a5fa" } : {}),
              })}
            >
              <span>{icon}</span>
              <span style={{ flex: 1 }}>{label}</span>
              {label === "События" && unreadCount > 0 && <span style={s.badge}>{unreadCount}</span>}
            </NavLink>
          ))}
        </nav>
        {showLogout && (
          <button
            onClick={onLogout}
            style={{
              margin: 14, padding: "9px 0", borderRadius: 8,
              border: "1px solid #1e2a45", background: "transparent",
              color: "#64748b", fontSize: 13, cursor: "pointer",
            }}
          >
            ⏻ Выйти
          </button>
        )}
      </aside>
    </>
  );
}

function MobileTabBar({ onMore }) {
  const { unreadCount } = useApp();
  const loc = useLocation();
  return (
    <div style={s.tabbar}>
      {MOBILE_TABS.map((path) => {
        const item = NAV.find((n) => n.path === path);
        const active = path === "/" ? loc.pathname === "/" : loc.pathname.startsWith(path);
        return (
          <NavLink key={path} to={path} style={s.tab(active)}>
            <span style={s.tabIcon}>{item.icon}</span>
            <span>{item.label}</span>
            {path === "/alerts" && unreadCount > 0 && <span style={s.tabBadge}>{unreadCount}</span>}
          </NavLink>
        );
      })}
      <button style={s.tab(false)} onClick={onMore}>
        <span style={s.tabIcon}>☰</span>
        <span>Ещё</span>
      </button>
    </div>
  );
}

function AppShell({ onLogout, showLogout }) {
  const { handleWSEvent } = useApp();
  useWebSocket(handleWSEvent);
  const isMobile = useIsMobile();
  const [drawerOpen, setDrawerOpen] = useState(false);

  return (
    <BrowserRouter>
      <div style={s.layout}>
        <Sidebar
          mobile={isMobile}
          open={!isMobile || drawerOpen}
          onClose={() => setDrawerOpen(false)}
          onLogout={onLogout}
          showLogout={showLogout}
        />

        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
          {isMobile && (
            <div style={s.topbar}>
              <button style={s.burger} onClick={() => setDrawerOpen(true)}>☰</button>
              <span style={s.topTitle}>🛡 FAMILY SECURITY</span>
            </div>
          )}
          <main style={s.main(isMobile)}>
            <Routes>
              <Route path="/"             element={<Overview />} />
              <Route path="/locations"    element={<Locations />} />
              <Route path="/devices"      element={<Devices />} />
              <Route path="/dns"          element={<DNSActivity />} />
              <Route path="/alerts"       element={<Alerts />} />
              <Route path="/map"          element={<NetworkMap />} />
              <Route path="/connections"  element={<Connections />} />
              <Route path="/bandwidth"    element={<Bandwidth />} />
              <Route path="/threats"      element={<ThreatIntel />} />
              <Route path="/feed"         element={<RealtimeFeed />} />
              <Route path="/assistant"    element={<Assistant />} />
              <Route path="/settings"     element={<Settings />} />
            </Routes>
          </main>
        </div>

        {isMobile && <MobileTabBar onMore={() => setDrawerOpen(true)} />}
      </div>
      <ToastLayer />
    </BrowserRouter>
  );
}

export default function App() {
  // authState: "loading" | "login" | "ok"
  const [authState, setAuthState] = useState("loading");
  const [demoMode, setDemoMode] = useState(false);

  const checkAuth = useCallback(async () => {
    try {
      const h = await api.health();
      if (h.demo_mode) {
        setDemoMode(true);
        setAuthState("ok");
        return;
      }
    } catch {}
    setDemoMode(false);
    setAuthState(auth.isLoggedIn() ? "ok" : "login");
  }, []);

  useEffect(() => {
    checkAuth();
    const onUnauthorized = () => setAuthState("login");
    window.addEventListener("fs:unauthorized", onUnauthorized);
    return () => window.removeEventListener("fs:unauthorized", onUnauthorized);
  }, [checkAuth]);

  const logout = () => {
    auth.clearToken();
    setAuthState("login");
  };

  if (authState === "loading") {
    return (
      <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: "#475569" }}>
        Загрузка...
      </div>
    );
  }

  if (authState === "login") {
    return <Login onLogin={() => setAuthState("ok")} />;
  }

  return (
    <AppProvider>
      <AppShell onLogout={logout} showLogout={!demoMode} />
    </AppProvider>
  );
}
