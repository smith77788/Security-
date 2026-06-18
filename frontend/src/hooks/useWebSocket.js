import { useEffect, useRef } from "react";

const WS_URL = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/events`;
const RECONNECT_DELAY = 3000;

export function useWebSocket(onMessage) {
  const wsRef = useRef(null);
  const timerRef = useRef(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    let active = true;

    function connect() {
      if (!active) return;
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        console.debug("[WS] connected");
        // Start client-side keepalive
        timerRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 25000);
      };

      ws.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.type !== "pong" && evt.type !== "ping") {
            onMessageRef.current(evt);
          }
        } catch {}
      };

      ws.onclose = () => {
        clearInterval(timerRef.current);
        if (active) {
          console.debug("[WS] disconnected, reconnecting in %dms", RECONNECT_DELAY);
          setTimeout(connect, RECONNECT_DELAY);
        }
      };

      ws.onerror = () => ws.close();
    }

    connect();

    return () => {
      active = false;
      clearInterval(timerRef.current);
      wsRef.current?.close();
    };
  }, []);
}
