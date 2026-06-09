import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import (
    DEMO_MODE, CORS_ORIGINS, SCAN_INTERVAL_SECONDS,
    DNS_CAPTURE_ENABLED, NETWORK_INTERFACE, ADMIN_PASSWORD,
)
from database import init_db, SessionLocal
from services.realtime import manager
from routers import devices, dns, alerts, dashboard, assistant, settings as settings_router
from routers import locations, ingest, ws as ws_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("main")

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("Database initialised")

    # Wire the running event loop into the realtime manager for thread-safe emit
    manager.set_loop(asyncio.get_event_loop())

    if DEMO_MODE:
        from services.demo_seed import seed
        seed()
        log.info("Demo data loaded (3 locations)")
    else:
        from services.device_scanner import run_scan
        run_scan()

        def _run_anomaly():
            from services.anomaly_detector import run_all_checks
            db = SessionLocal()
            try:
                run_all_checks(db)
            finally:
                db.close()

        def _run_retention():
            from routers.settings import apply_retention
            db = SessionLocal()
            try:
                apply_retention(db)
            finally:
                db.close()

        def _check_offline_locations():
            """Mark locations offline if no heartbeat for >2 minutes."""
            from datetime import datetime, timedelta
            from models import Location
            db = SessionLocal()
            try:
                cutoff = datetime.utcnow() - timedelta(minutes=2)
                stale = db.query(Location).filter(
                    Location.is_online == True,  # noqa: E712
                    Location.last_heartbeat < cutoff,
                ).all()
                for loc in stale:
                    loc.is_online = False
                    manager.emit_location_status(loc.id, loc.name, online=False)
                if stale:
                    db.commit()
            finally:
                db.close()

        scheduler.add_job(run_scan, IntervalTrigger(seconds=SCAN_INTERVAL_SECONDS), id="scan", replace_existing=True)
        scheduler.add_job(_run_anomaly, IntervalTrigger(minutes=5), id="anomaly", replace_existing=True)
        scheduler.add_job(_run_retention, IntervalTrigger(hours=24), id="retention", replace_existing=True)
        scheduler.add_job(_check_offline_locations, IntervalTrigger(minutes=1), id="offline_check", replace_existing=True)

        if DNS_CAPTURE_ENABLED:
            from services import dns_monitor
            dns_monitor.start(NETWORK_INTERFACE)

        scheduler.start()
        log.info("Scheduler started")

    yield
    scheduler.shutdown(wait=False)
    log.info("Shutdown")


app = FastAPI(
    title="Family Security",
    description="Home Network Guardian — multi-location, real-time defensive monitoring",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROTECTED = ["/api/settings", "/api/locations"]


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Ingest routes use API key auth, not admin token
    if request.url.path.startswith("/api/ingest"):
        return await call_next(request)
    if not DEMO_MODE and any(request.url.path.startswith(p) for p in PROTECTED):
        token = request.headers.get("X-Admin-Token", "")
        if token != ADMIN_PASSWORD:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


for r in [devices, dns, alerts, dashboard, assistant, settings_router, locations, ingest]:
    app.include_router(r.router)
app.include_router(ws_router.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "demo_mode": DEMO_MODE, "dns_capture": DNS_CAPTURE_ENABLED, "version": "2.0.0"}
