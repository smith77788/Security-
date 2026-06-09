"""
WebSocket connection manager.
Thread-safe broadcast from both async handlers and APScheduler threads.
"""
import asyncio
import logging
from typing import Optional
from fastapi import WebSocket

log = logging.getLogger("realtime")


class RealtimeManager:
    def __init__(self):
        self._connections: list[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        log.debug("WS client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)
        log.debug("WS client disconnected (%d remaining)", len(self._connections))

    async def broadcast(self, event: dict):
        if not self._connections:
            return
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)

    def emit(self, event: dict):
        """Call from any thread (scheduler, scanner). Thread-safe."""
        if not self._connections or self._loop is None:
            return
        if self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(event), self._loop)

    def emit_alert(self, alert, location_name: str = ""):
        self.emit({
            "type": "alert",
            "location_id": alert.location_id,
            "location_name": location_name,
            "payload": {
                "id": alert.id,
                "severity": alert.severity,
                "alert_type": alert.alert_type,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
            },
        })

    def emit_new_device(self, device, location_name: str = ""):
        self.emit({
            "type": "new_device",
            "location_id": device.location_id,
            "location_name": location_name,
            "payload": {
                "id": device.id,
                "mac": device.mac,
                "ip": device.ip,
                "vendor": device.vendor or "Unknown",
                "hostname": device.hostname,
            },
        })

    def emit_score(self, location_id: int, location_name: str, score: int, grade: str):
        self.emit({
            "type": "score_update",
            "location_id": location_id,
            "location_name": location_name,
            "payload": {"score": score, "grade": grade},
        })

    def emit_location_status(self, location_id: int, name: str, online: bool):
        self.emit({
            "type": "location_status",
            "location_id": location_id,
            "location_name": name,
            "payload": {"online": online},
        })


manager = RealtimeManager()
