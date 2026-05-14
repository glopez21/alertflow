"""AlertFlow FastAPI application."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from api.deps import get_store
from api.health import health, set_start_time
from api.routes import router as alerts_router
from api.enrich import router as enrich_router

API_KEY = os.environ.get("ALERTFLOW_API_KEY", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    set_start_time()
    yield
    store = get_store()
    store.close()


app = FastAPI(
    title="AlertFlow",
    description="SOC Alert Triage API",
    version="0.6.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALERTFLOW_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    if not API_KEY:
        return await call_next(request)
    if request.url.path == "/api/health":
        return await call_next(request)
    if request.method == "OPTIONS":
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    api_key = request.headers.get("X-API-Key", "")
    if auth == f"Bearer {API_KEY}" or api_key == API_KEY:
        return await call_next(request)
    return Response(status_code=401, content="Unauthorized")


app.include_router(alerts_router)
app.include_router(enrich_router)


@app.get("/api/health", tags=["health"])
async def health_check():
    return await health()