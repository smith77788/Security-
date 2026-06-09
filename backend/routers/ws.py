import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.realtime import manager

router = APIRouter()
log = logging.getLogger("ws")


@router.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep-alive: receive pings from client (or just wait)
            data = await asyncio.wait_for(ws.receive_text(), timeout=30)
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except asyncio.TimeoutError:
        # Send server-side keepalive
        try:
            await ws.send_json({"type": "ping"})
        except Exception:
            manager.disconnect(ws)
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as e:
        log.debug("WS error: %s", e)
        manager.disconnect(ws)
