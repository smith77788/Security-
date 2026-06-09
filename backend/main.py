import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from config import (
    DEMO_MODE, CORS_ORIGINS, SCAN_INTERVAL_SECONDS,
    DNS_CAPTURE_ENABLED, NETWORK_INTERFACE, ADMIN_PASSWORD,
)
from database import init_db, SessionLocal
from routers import devices, dns, alerts, dashboard, assistant, settings as settings_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("main")

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("Database initialised")

    if DEMO_MODE:
        from services.demo_seed import seed
        seed()
        log.info("Demo data loaded")
    else:
        # Initial device scan
        from services.device_scanner import run_scan
        run_scan()

        scheduler.add_job(
            run_scan,
            trigger=IntervalTrigger(seconds=SCAN_INTERVAL_SECONDS),
            id="device_scan",
            replace_existing=True,
        )

        # Anomaly checks every 5 minutes
        def _run_anomaly():
            from services.anomaly_detector import run_all_checks
            db = SessionLocal()
            try:
                run_all_checks(db)
            finally:
                db.close()

        scheduler.add_job(_run_anomaly, trigger=IntervalTrigger(minutes=5), id="anomaly_check", replace_existing=True)

        # Log retention daily
        def _run_retention():
            from routers.settings import apply_retention
            db = SessionLocal()
            try:
                apply_retention(db)
            finally:
                db.close()

        scheduler.add_job(_run_retention, trigger=IntervalTrigger(hours=24), id="retention", replace_existing=True)

        if DNS_CAPTURE_ENABLED:
            from services import dns_monitor
            dns_monitor.start(NETWORK_INTERFACE)

        scheduler.start()
        log.info("Scheduler started (scan interval: %ds)", SCAN_INTERVAL_SECONDS)

    yield

    scheduler.shutdown(wait=False)
    log.info("Shutdown complete")


app = FastAPI(
    title="Family Security",
    description="Home Network Guardian — local-only defensive monitoring",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple token auth middleware (optional — skip in demo mode)
PROTECTED_PREFIXES = ["/api/settings"]


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if not DEMO_MODE and any(request.url.path.startswith(p) for p in PROTECTED_PREFIXES):
        token = request.headers.get("X-Admin-Token", "")
        if token != ADMIN_PASSWORD:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)


app.include_router(devices.router)
app.include_router(dns.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(assistant.router)
app.include_router(settings_router.router)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "demo_mode": DEMO_MODE,
        "dns_capture": DNS_CAPTURE_ENABLED,
    }
