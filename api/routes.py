"""Alert CRUD endpoints."""

from fastapi import APIRouter, Depends, HTTPException

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

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _to_response(alert: dict | None) -> AlertResponse:
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse(**alert)


@router.get("", response_model=AlertListResponse)
def list_alerts(
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
    )


@router.post("", response_model=AlertResponse, status_code=201)
def create_alert(body: AlertCreate, store: AlertStore = Depends(get_store)):
    alert = store.add_alert(body.title, body.severity, body.source, body.ioc)
    return AlertResponse(**alert)


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, store: AlertStore = Depends(get_store)):
    alert = store.get_alert(alert_id)
    return _to_response(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(alert_id: int, body: StatusUpdate, store: AlertStore = Depends(get_store)):
    alert = store.update_status(alert_id, body.status, body.analyst, body.fp_reason)
    return _to_response(alert)


@router.patch("/{alert_id}/enrichment", response_model=AlertResponse)
def update_enrichment(alert_id: int, body: EnrichUpdate, store: AlertStore = Depends(get_store)):
    alert = store.update_enrichment(alert_id, body.enrichment)
    return _to_response(alert)


@router.post("/{alert_id}/notes", response_model=AlertResponse)
def add_note(alert_id: int, body: NoteCreate, store: AlertStore = Depends(get_store)):
    alert = store.add_note(alert_id, body.note, body.analyst)
    return _to_response(alert)


@router.delete("/{alert_id}", status_code=204)
def delete_alert(alert_id: int, store: AlertStore = Depends(get_store)):
    if not store.delete_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")