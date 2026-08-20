"""AlertFlow FastAPI application — production-ready."""

import asyncio
import os

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
from auth import create_api_key_auth_middleware
from kafka_consumer import run_kafka_consumer
from logging_config import RequestLoggingMiddleware, setup_logging

setup_logging()

RATE_LIMIT = os.environ.get("ALERTFLOW_RATE_LIMIT", "60/minute")

limiter = Limiter(key_func=get_remote_address)

_kafka_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _kafka_task
    set_start_time()

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


app = FastAPI(
    title="AlertFlow",
    description="SOC Alert Triage API — production-ready",
    version="0.7.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALERTFLOW_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_key_auth = create_api_key_auth_middleware()
app.add_middleware(RequestLoggingMiddleware)

Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

app.include_router(alerts_router)
app.include_router(enrich_router)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    return await api_key_auth(request, call_next)


@app.get("/api/health", tags=["health"])
@limiter.exempt
async def health_check(request: Request):
    return await health()


@app.get("/api/audit/auth", tags=["auth"])
async def auth_audit(limit: int = 100):
    from auth import get_auth_audit
    return {"entries": get_auth_audit(limit)}
