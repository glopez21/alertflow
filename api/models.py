"""Pydantic models for the AlertFlow API request/response contracts.

All models use Pydantic v2-style ``BaseModel`` with ``Field`` constraints to
enforce input validation at the API boundary, ensuring that malformed payloads
are rejected with clear 422 error responses before reaching business logic.

Field length limits are intentionally conservative to prevent abuse via
oversized payloads while remaining generous enough for realistic SOC data.
"""

from typing import Literal

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    """Inbound payload for creating a new alert.

    Attributes:
        title: Short description of the alert (required, max 500 chars).
        severity: SOC priority level — P1 (critical) through P4 (info), default P3.
        source: Origin system or analyst (default "manual").
        ioc: Optional indicator of compromise associated with the alert.
    """
    title: str = Field(max_length=500)
    severity: Literal["P1", "P2", "P3", "P4"] = "P3"
    source: str = Field(default="manual", max_length=100)
    ioc: str = Field(default="", max_length=500)


class AlertResponse(BaseModel):
    """Full alert representation returned to API consumers.

    Includes all mutable fields (status, analyst, enrichment, notes) so
    clients always see the latest state without extra round-trips.
    """
    id: int
    title: str
    severity: str
    source: str
    ioc: str = ""
    status: str
    created_at: str
    updated_at: str
    analyst: str = ""
    fp_reason: str = ""
    # Enrichment is a free-form dict holding external feed results
    # (VirusTotal, AbuseIPDB, etc.) — shape varies by IOC type.
    enrichment: dict = Field(default_factory=dict)
    # Notes is an append-only list of {note, analyst, timestamp} dicts.
    notes: list = Field(default_factory=list)


class AlertListResponse(BaseModel):
    """Paginated list of alerts with metadata for cursor-based navigation.

    ``has_more`` allows clients to know whether another page exists without
    requiring a COUNT(*) query on every request.
    """
    alerts: list[AlertResponse]
    total: int
    limit: int
    offset: int
    has_more: bool = False


class NoteCreate(BaseModel):
    """Inbound payload for adding an analyst note to an alert.

    The 5000-char limit accommodates detailed investigation notes while
    preventing storage abuse.
    """
    note: str = Field(max_length=5000)
    analyst: str = Field(default="", max_length=100)


class StatusUpdate(BaseModel):
    """Transition an alert through the SOC triage lifecycle.

    The ``status`` Literal constrains values to the defined workflow states,
    preventing invalid transitions at the API level. ``fp_reason`` is expected
    when closing as false-positive, but enforcement of that business rule is
    handled at the service layer, not here.
    """
    status: Literal["Open", "In Progress", "Escalated", "Closed", "Closed - FP", "Closed - Benign", "Closed - Responded"]
    analyst: str = Field(default="", max_length=100)
    fp_reason: str = Field(default="", max_length=1000)


class EnrichUpdate(BaseModel):
    """Replace the enrichment payload on an alert.

    The dict structure is intentionally unvalidated here because enrichment
    schemas vary by IOC type (IP vs. hash vs. domain).
    """
    enrichment: dict


class EnrichRequest(BaseModel):
    """Request body for the on-demand enrichment endpoint.

    ``target_type`` is optional; when omitted the system auto-detects the IOC
    type from the target string using heuristic/pattern matching.
    """
    target: str
    target_type: str | None = None


class EnrichResponse(BaseModel):
    """Enrichment result containing the resolved IOC type and check outcomes."""
    target: str
    target_type: str
    checks: dict


class HealthResponse(BaseModel):
    """Health probe response used by load-balancers and k8s probes.

    ``db_status`` reports "connected" or "error"; ``alert_count`` uses -1 as
    a sentinel value when the database is unreachable.
    """
    status: str
    version: str
    uptime: str
    db_status: str = "unknown"
    alert_count: int = -1