"""Alert CRUD endpoints with rate limiting and idempotency.

Provides the core REST API for SOC analysts to create, query, update, annotate,
and delete alerts. Each endpoint is independently rate-limited via SlowAPI and
the store dependency is injected through FastAPI's Depends() mechanism.

Design decisions:
- Read endpoints allow 120 req/min; mutating endpoints allow 60 req/min;
  destructive (DELETE) endpoints allow 30 req/min.
- ``POST /api/alerts`` supports an optional ``idempotency_key`` query parameter
  to prevent duplicate alert creation from retrying producers.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.deps import get_store
from api.models import (
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    EnrichUpdate,
    NoteCreate,
    StatusUpdate,
)
from db import AlertStore
from logging_config import get_logger

logger = get_logger("alertflow.api")

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
limiter = Limiter(key_func=get_remote_address)


def _to_response(alert: dict | None) -> AlertResponse:
    """Convert a raw store dict to a Pydantic AlertResponse.

    Raises 404 if the alert does not exist (store returned None).
    """
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse(**alert)


@router.get("", response_model=AlertListResponse)
@limiter.limit("120/minute")
def list_alerts(
    request: Request,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    store: AlertStore = Depends(get_store),
):
    """List alerts with optional status filter and cursor-based pagination.

    Args:
        status: Optional status filter (e.g. "Open", "Closed - FP").
        limit: Page size, clamped to [1, 1000] (default 100).
        offset: Zero-based offset for pagination (clamped to >= 0).
    """
    # Clamp pagination params to safe bounds to prevent abuse or errors.
    if limit < 1 or limit > 1000:
        limit = 100
    if offset < 0:
        offset = 0
    alerts, total = store.list_alerts(status, limit=limit, offset=offset)
    return AlertListResponse(
        alerts=[AlertResponse(**a) for a in alerts],
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(alerts)) < total,
    )


@router.post("", response_model=AlertResponse, status_code=201)
@limiter.limit("60/minute")
def create_alert(
    request: Request,
    body: AlertCreate,
    idempotency_key: str | None = None,
    store: AlertStore = Depends(get_store),
):
    """Create a new alert.

    When ``idempotency_key`` is provided, the store checks for an existing
    alert with the same title+source+IOC combination and returns it instead of
    creating a duplicate. This is critical for at-least-once Kafka ingestion
    where retries can produce duplicate deliveries.
    """
    if idempotency_key:
        dup = store.find_duplicate(body.title, body.source, body.ioc)
        if dup:
            logger.info("alert.idempotent_hit", alert_id=dup["id"], title=body.title)
            return AlertResponse(**dup)

    alert = store.add_alert(body.title, body.severity, body.source, body.ioc)

    logger.info("alert.created", alert_id=alert["id"], title=body.title, severity=body.severity, source=body.source)
    return AlertResponse(**alert)


@router.get("/{alert_id}", response_model=AlertResponse)
@limiter.limit("120/minute")
def get_alert(request: Request, alert_id: int, store: AlertStore = Depends(get_store)):
    """Retrieve a single alert by its numeric ID."""
    alert = store.get_alert(alert_id)
    return _to_response(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
@limiter.limit("60/minute")
def update_alert_status(
    request: Request,
    alert_id: int,
    body: StatusUpdate,
    store: AlertStore = Depends(get_store),
):
    """Transition an alert's status and optionally record the analyst and FP reason.

    Status values follow the SOC triage lifecycle defined in StatusUpdate.
    """
    alert = store.update_status(alert_id, body.status, body.analyst, body.fp_reason)
    if alert:
        logger.info("alert.status_updated", alert_id=alert_id, status=body.status, analyst=body.analyst)
    return _to_response(alert)


@router.patch("/{alert_id}/enrichment", response_model=AlertResponse)
@limiter.limit("60/minute")
def update_enrichment(
    request: Request,
    alert_id: int,
    body: EnrichUpdate,
    store: AlertStore = Depends(get_store),
):
    """Replace the enrichment payload attached to an alert.

    The enrichment dict is typically produced by the /api/enrich endpoint or
    the automated pipeline and contains VirusTotal, AbuseIPDB, etc. results.
    """
    alert = store.update_enrichment(alert_id, body.enrichment)
    return _to_response(alert)


@router.post("/{alert_id}/notes", response_model=AlertResponse)
@limiter.limit("60/minute")
def add_note(
    request: Request,
    alert_id: int,
    body: NoteCreate,
    store: AlertStore = Depends(get_store),
):
    """Append an analyst note to an alert's note history.

    Notes are immutable once added; they form an append-only audit trail.
    """
    alert = store.add_note(alert_id, body.note, body.analyst)
    if alert:
        logger.info("alert.note_added", alert_id=alert_id, analyst=body.analyst)
    return _to_response(alert)


@router.delete("/{alert_id}", status_code=204)
@limiter.limit("30/minute")
def delete_alert(request: Request, alert_id: int, store: AlertStore = Depends(get_store)):
    """Permanently remove an alert.

    Returns 404 if the alert does not exist. Delete is intentionally throttled
    more aggressively (30/min) as a destructive operation.
    """
    if not store.delete_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    logger.info("alert.deleted", alert_id=alert_id)
