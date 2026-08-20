"""Alert CRUD endpoints with rate limiting and idempotency."""

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
    alert = store.add_note(alert_id, body.note, body.analyst)
    if alert:
        logger.info("alert.note_added", alert_id=alert_id, analyst=body.analyst)
    return _to_response(alert)


@router.delete("/{alert_id}", status_code=204)
@limiter.limit("30/minute")
def delete_alert(request: Request, alert_id: int, store: AlertStore = Depends(get_store)):
    if not store.delete_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    logger.info("alert.deleted", alert_id=alert_id)
