"""Shared models for AlertFlow."""

from pydantic import BaseModel


class ThreatPulseWebhookPayload(BaseModel):
    source: str = "alertflow"
    event: str = "alert.triaged"
    severity: str
    title: str
    description: str = ""
    ioc: str = ""
    analyst: str = ""
    action: str = ""