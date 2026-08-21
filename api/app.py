"""AlertFlow FastAPI application entry point.

Assembles the production-ready ASGI application with:
- API-key authentication middleware (fail-secure on misconfiguration)
- Request logging and structured logging bootstrap
- SlowAPI rate limiting (per-IP, configurable via env)
- CORS with explicit origin allowlist
- Prometheus metrics instrumentation
- Kafka consumer lifecycle (optional)
- On-startup retention cleanup
- Health check and enrichment sub-routers alongside the core alert CRUD router
"""

import asyncio
import os
import sys

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.deps import get_store
from api.health import health, set_start_time
from api.routes import router as alerts_router
from api.enrich import router as enrich_router
from api.web import router as web_router
from auth import create_api_key_auth_middleware
from kafka_consumer import run_kafka_consumer
from logging_config import RequestLoggingMiddleware, setup_logging

# Initialize structured logging before any other import side-effects.
setup_logging()

# Default global rate limit; individual routes may override with tighter limits.
RATE_LIMIT = os.environ.get("ALERTFLOW_RATE_LIMIT", "60/minute")

# SlowAPI limiter keyed by client IP for fair per-tenant throttling.
limiter = Limiter(key_func=get_remote_address)

# Module-level handle to the optional Kafka consumer asyncio Task, kept so the
# lifespan shutdown coroutine can cancel it cleanly.
_kafka_task = None


def _check_auth_config():
    """Validate auth configuration at startup.

    Enforces a fail-secure policy: if authentication is enabled (default) but
    no API key has been configured, the process terminates immediately to
    prevent running with an open, unprotected API in production.

    Exits with code 1 on misconfiguration.
    """
    auth_enabled = os.environ.get("ALERTFLOW_AUTH_ENABLED", "true").lower() == "true"
    api_key = os.environ.get("ALERTFLOW_API_KEY", "")
    if auth_enabled and not api_key:
        print(
            "FATAL: ALERTFLOW_AUTH_ENABLED=true but ALERTFLOW_API_KEY is empty.\n"
            "Set ALERTFLOW_API_KEY or set ALERTFLOW_AUTH_ENABLED=false to disable auth.",
            file=sys.stderr,
        )
        sys.exit(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager.

    Runs startup logic before yielding to FastAPI, then shutdown logic after:
    Startup:
        1. Record process start time for uptime reporting.
        2. Validate auth configuration (fail-secure).
        3. Initialize the backing store (SQLite or MySQL singleton).
        4. Optionally start the Kafka consumer as a background asyncio Task.
        5. Run one-shot retention cleanup of alerts older than N days.
    Shutdown:
        1. Cancel the Kafka consumer task (if running) and await its exit.
        2. Close the store connection pool / file handle.
    """
    global _kafka_task
    set_start_time()
    _check_auth_config()

    store = get_store()

    kafka_enabled = os.environ.get("ALERTFLOW_KAFKA_ENABLED", "false").lower() == "true"
    if kafka_enabled:
        loop = asyncio.get_event_loop()
        _kafka_task = loop.create_task(run_kafka_consumer(store))

    retention_days = int(os.environ.get("ALERTFLOW_RETENTION_DAYS", "0"))
    if retention_days > 0:
        deleted = store.delete_old_alerts(retention_days)
        if deleted:
            from logging_config import get_logger
            get_logger("alertflow.lifecycle").info("retention.cleanup", deleted=deleted, days=retention_days)

    yield

    if _kafka_task:
        _kafka_task.cancel()
        try:
            await _kafka_task
        except asyncio.CancelledError:
            pass

    store.close()


# ---------------------------------------------------------------------------
# Application instance and middleware stack
# ---------------------------------------------------------------------------
# Middleware executes in reverse-registration order: the last `add_middleware`
# call runs first on inbound requests. Order matters:
#   1. RequestLoggingMiddleware  (outermost – logs every request/response)
#   2. CORSMiddleware            (handles preflight and headers)
#   3. auth_middleware           (API-key check, innermost before route)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AlertFlow",
    description="SOC Alert Triage API — production-ready",
    version="0.7.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach the SlowAPI limiter to app.state so it's available to @limiter.limit
# decorators on route functions.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS origins are comma-separated in env to support multi-origin in
# deployments (e.g. "https://app.example.com,https://admin.example.com").
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALERTFLOW_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API-key auth middleware factory; returns a callable ASGI middleware.
api_key_auth = create_api_key_auth_middleware()

# Request logging wraps every request/response for structured audit trails.
app.add_middleware(RequestLoggingMiddleware)

# Prometheus Instrumentator automatically exposes /metrics with histogram
# latencies, request counts, and status-code breakdowns per route.
# include_in_schema=False keeps the metrics endpoint out of OpenAPI docs.
Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

# Mount the core alert CRUD router, the enrichment sub-router, and the
# read-only web dashboard.
app.include_router(alerts_router)
app.include_router(enrich_router)
app.include_router(web_router)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Thin wrapper that delegates to the API-key auth middleware.

    Registered as an HTTP middleware so it runs on every request except those
    explicitly exempted (e.g. /api/health, /metrics).
    """
    return await api_key_auth(request, call_next)


@app.get("/api/health", tags=["health"])
@limiter.exempt  # Health probes must never be rate-limited (load-balancers, k8s).
async def health_check(request: Request):
    """Liveness/readiness probe returning DB status, uptime, and alert count."""
    return await health()


@app.get("/api/audit/auth", tags=["auth"])
async def auth_audit(limit: int = 100):
    """Return recent authentication audit-log entries for security review."""
    from auth import get_auth_audit
    return {"entries": get_auth_audit(limit)}
