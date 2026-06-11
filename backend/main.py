import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import (
    DEMO_MODE, CORS_ORIGINS, SCAN_INTERVAL_SECONDS,
    DNS_CAPTURE_ENABLED, ADMIN_PASSWORD,
    OPENWRT_HOST, OPENWRT_SYSLOG_PORT,
)
from database import init_db, SessionLocal
from services.realtime import manager
from services import auto_config
from routers import (
    devices, dns, alerts, dashboard, assistant,
    settings as settings_router, locations, ingest,
    ws as ws_router, network_map, intel, auth as auth_router,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("main")

scheduler = AsyncIOScheduler(timezone="UTC")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("Database initialised")
    manager.set_loop(asyncio.get_event_loop())

    # Interactive Telegram bot (no-op until token + chat_id are configured)
    from services.telegram_bot import bot as tg_bot
    tg_bot.start()

    if DEMO_MODE:
        from services.demo_seed import seed
        seed()
        log.info("Demo data seeded (3 locations, enriched)")
    else:
        # Auto-detect network config
        net = auto_config.get()
        log.info("Network: interface=%s subnet=%s gateway=%s",
                 net["interface"], net["subnet"], net["gateway"])

        # Первый запуск — создать локацию "Мой дом" если нет ни одной
        _setup_db = SessionLocal()
        try:
            from models import Location
            if _setup_db.query(Location).count() == 0:
                _home = Location(
                    name="Мой дом",
                    icon="🏠",
                    color="#3b82f6",
                    timezone="UTC",
                    is_online=True,
                )
                _setup_db.add(_home)
                _setup_db.commit()
                log.info("Создана локация 'Мой дом' (первый запуск)")
        except Exception as e:
            log.warning("Ошибка создания локации: %s", e)
        finally:
            _setup_db.close()

        # Load threat intel on startup (non-blocking)
        import threading
        threading.Thread(
            target=_load_threat_intel, daemon=True, name="threat-intel"
        ).start()

        # Initial device scan
        from services.device_scanner import run_scan
        run_scan()

        # OpenWrt router integration (syslog + SSH polling)
        from services import syslog_server, openwrt_client
        syslog_server.start(OPENWRT_SYSLOG_PORT)
        if openwrt_client.load_from_settings() or OPENWRT_HOST:
            if OPENWRT_HOST:
                openwrt_client.configure(host=OPENWRT_HOST)
            openwrt_client.start()
            log.info("OpenWrt client started")

        # Start deep packet monitor if available
        if DNS_CAPTURE_ENABLED:
            from services import deep_monitor
            deep_monitor.start(net["interface"])

        def _run_anomaly():
            from services.anomaly_detector import run_all_checks
            from services.beaconing import run_and_alert
            db = SessionLocal()
            try:
                run_all_checks(db)
                run_and_alert(db)
            finally:
                db.close()

        def _run_scan():
            from services.device_scanner import run_scan
            run_scan()

        def _check_offline():
            from datetime import datetime, timedelta
            from models import Location
            db = SessionLocal()
            try:
                cutoff = datetime.utcnow() - timedelta(minutes=2)
                stale = db.query(Location).filter(
                    Location.is_online == True,   # noqa: E712
                    Location.last_heartbeat < cutoff,
                ).all()
                for loc in stale:
                    loc.is_online = False
                    manager.emit_location_status(loc.id, loc.name, online=False)
                if stale:
                    db.commit()
            finally:
                db.close()

        def _run_retention():
            from routers.settings import apply_retention
            db = SessionLocal()
            try:
                apply_retention(db)
            finally:
                db.close()

        def _sample_bandwidth():
            from services.bandwidth_tracker import sample_network
            net_cfg = auto_config.get()
            sample_network(net_cfg["interface"])

        def _beaconing():
            from services.beaconing import run_and_alert
            db = SessionLocal()
            try:
                run_and_alert(db)
            finally:
                db.close()

        def _refresh_threat_intel():
            _load_threat_intel()

        # Синхронизировать iptables с заблокированными устройствами из БД
        from services.network_blocker import sync_blocks
        _sync_db = SessionLocal()
        try:
            from models import BlockedDevice
            blocked = [b.mac for b in _sync_db.query(BlockedDevice).all()]
            sync_blocks(blocked)
        finally:
            _sync_db.close()

        scheduler.add_job(_run_scan,             IntervalTrigger(seconds=SCAN_INTERVAL_SECONDS), id="scan")
        scheduler.add_job(_run_anomaly,          IntervalTrigger(minutes=5),   id="anomaly")
        scheduler.add_job(_check_offline,        IntervalTrigger(minutes=1),   id="offline")
        scheduler.add_job(_run_retention,        IntervalTrigger(hours=24),    id="retention")
        scheduler.add_job(_sample_bandwidth,     IntervalTrigger(minutes=1),   id="bandwidth")
        scheduler.add_job(_beaconing,            IntervalTrigger(minutes=10),  id="beaconing")
        scheduler.add_job(_refresh_threat_intel, IntervalTrigger(hours=24),    id="threat_intel")
        scheduler.start()
        log.info("Scheduler started")

    yield
    scheduler.shutdown(wait=False)
    log.info("Shutdown complete")


def _load_threat_intel():
    try:
        from services.threat_intel import load_all
        load_all()
    except Exception as e:
        log.error("Threat intel load failed: %s", e)


app = FastAPI(
    title="Family Security",
    description="Home Network Guardian — full-spectrum passive monitoring",
    version="3.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths that never require a JWT:
#  - /api/auth/login  — the login endpoint itself
#  - /api/ingest/*    — agents authenticate with their own X-API-Key
#  - /api/health      — used by Docker healthchecks / agents
PUBLIC_PATHS = ("/api/auth/login", "/api/ingest", "/api/health")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api") or path.startswith(PUBLIC_PATHS):
        return await call_next(request)
    if DEMO_MODE:
        return await call_next(request)

    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
    # Legacy header kept for backwards compatibility with old agents/scripts
    if not token and request.headers.get("X-Admin-Token", "") == ADMIN_PASSWORD:
        return await call_next(request)
    try:
        from services.auth_utils import decode_token
        decode_token(token)
    except Exception:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


for r in [auth_router, devices, dns, alerts, dashboard, assistant,
          settings_router, locations, ingest, network_map, intel]:
    app.include_router(r.router)
app.include_router(ws_router.router)

# Раздача собранного React-приложения (для запуска без Docker/nginx, например в Termux)
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str, request: Request):
        """Все не-API пути → index.html (SPA routing)."""
        if full_path.startswith("api"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        index = _STATIC_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return JSONResponse(status_code=404, content={"detail": "Frontend not built"})


@app.get("/api/health")
def health():
    net = auto_config.get()
    from services.threat_intel import status as ti_status
    from services.network_blocker import is_available as fw_available
    return {
        "status": "ok",
        "version": "3.2.0",
        "demo_mode": DEMO_MODE,
        "dns_capture": DNS_CAPTURE_ENABLED,
        "firewall_available": fw_available(),
        "network": net,
        "threat_intel": ti_status(),
    }
