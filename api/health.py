"""Health check endpoint with database connectivity verification.

Exposes a lightweight liveness/readiness probe that reports:
- Application version
- Human-readable uptime since process start
- Database connectivity status (connected / error)
- Total alert count in the store

The start time is recorded once at application boot via ``set_start_time()``
(called from the lifespan handler) so that ``get_uptime()`` always reflects
the current process lifetime.
"""

import time

from api.models import HealthResponse

# Hard-coded version; kept in sync with the FastAPI app version string.
VERSION = "0.7.0"

# Process start time; set exactly once by set_start_time().
_start_time: float | None = None


def get_uptime() -> str:
    """Format elapsed seconds since process start as a human-readable string.

    Returns "0s" if start time has not been set. Uses the largest unit that
    keeps the value readable: seconds (<60), minutes (<60), or hours.
    """
    if _start_time is None:
        return "0s"
    elapsed = time.time() - _start_time
    if elapsed < 60:
        return f"{elapsed:.0f}s"
    if elapsed < 3600:
        return f"{elapsed / 60:.0f}m"
    return f"{elapsed / 3600:.1f}h"


def set_start_time():
    """Record the application start time. Called once during lifespan startup."""
    global _start_time
    _start_time = time.time()


async def health() -> HealthResponse:
    """Probe database connectivity and return aggregated health information.

    If the store raises an exception (connection refused, timeout, etc.),
    the status is reported as "error" with a sentinel alert_count of -1,
    allowing load-balancers and k8s probes to detect degraded state.
    """
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
