"""Health check endpoint with database connectivity."""

import time

from api.models import HealthResponse

VERSION = "0.7.0"
_start_time: float | None = None


def get_uptime() -> str:
    if _start_time is None:
        return "0s"
    elapsed = time.time() - _start_time
    if elapsed < 60:
        return f"{elapsed:.0f}s"
    if elapsed < 3600:
        return f"{elapsed / 60:.0f}m"
    return f"{elapsed / 3600:.1f}h"


def set_start_time():
    global _start_time
    _start_time = time.time()


async def health() -> HealthResponse:
    from api.deps import get_store
    store = get_store()
    try:
        count = store.count_alerts()
        db_status = "connected"
    except Exception:
        count = -1
        db_status = "error"

    return HealthResponse(
        status="healthy",
        version=VERSION,
        uptime=get_uptime(),
        db_status=db_status,
        alert_count=count,
    )
