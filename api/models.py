"""Pydantic models for the AlertFlow API."""

from typing import Literal

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    title: str = Field(max_length=500)
    severity: Literal["P1", "P2", "P3", "P4"] = "P3"
    source: str = Field(default="manual", max_length=100)
    ioc: str = Field(default="", max_length=500)


class AlertResponse(BaseModel):
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
    enrichment: dict = Field(default_factory=dict)
    notes: list = Field(default_factory=list)


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int
    limit: int
    offset: int
    has_more: bool = False


class NoteCreate(BaseModel):
    note: str = Field(max_length=5000)
    analyst: str = Field(default="", max_length=100)


class StatusUpdate(BaseModel):
    status: Literal["Open", "In Progress", "Escalated", "Closed", "Closed - FP", "Closed - Benign", "Closed - Responded"]
    analyst: str = Field(default="", max_length=100)
    fp_reason: str = Field(default="", max_length=1000)


class EnrichUpdate(BaseModel):
    enrichment: dict


class EnrichRequest(BaseModel):
    target: str
    target_type: str | None = None


class EnrichResponse(BaseModel):
    target: str
    target_type: str
    checks: dict


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime: str
    db_status: str = "unknown"
    alert_count: int = -1