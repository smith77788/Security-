import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { api } from "../api/client";

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [locations, setLocations] = useState([]);
  const [selectedLocationId, setSelectedLocationId] = useState(null); // null = all
  const [unreadCount, setUnreadCount] = useState(0);
  const [toasts, setToasts] = useState([]);       // real-time notifications
  const [liveEvents, setLiveEvents] = useState([]); // activity feed

  const refreshLocations = useCallback(() => {
    api.locationsSummary().then(setLocations).catch(console.error);
  }, []);

  const refreshUnread = useCallback(() => {
    api.alerts({ unread_only: true, hours: 168 })
      .then((a) => setUnreadCount(a.length))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshLocations();
    refreshUnread();
  }, []);

  const addToast = useCallback((event) => {
    const id = Date.now();
    setToasts((t) => [{ id, ...event }, ...t].slice(0, 5));
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  }, []);

  const addLiveEvent = useCallback((event) => {
    setLiveEvents((e) => [{ id: Date.now(), ts: new Date(), ...event }, ...e].slice(0, 50));
  }, []);

  const handleWSEvent = useCallback((event) => {
    if (event.type === "alert") {
      setUnreadCount((c) => c + 1);
      addToast(event);
      addLiveEvent(event);
      refreshLocations();
    } else if (event.type === "new_device") {
      addToast(event);
      addLiveEvent(event);
      refreshLocations();
    } else if (event.type === "location_status") {
      refreshLocations();
      addLiveEvent(event);
    } else if (event.type === "score_update") {
      refreshLocations();
    }
  }, [addToast, addLiveEvent, refreshLocations]);

  return (
    <AppContext.Provider value={{
      locations, refreshLocations,
      selectedLocationId, setSelectedLocationId,
      unreadCount, refreshUnread,
      toasts, handleWSEvent,
      liveEvents,
    }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  return useContext(AppContext);
}
