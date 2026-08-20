"""Shared models for AlertFlow.

Pydantic schemas used for request/response validation and webhook payloads
across the API layer.  Keeping models in a single module avoids circular
imports between routes and services.
"""

from pydantic import BaseModel


class ThreatPulseWebhookPayload(BaseModel):
    """Outbound webhook payload sent to ThreatPulse on alert triage events.

    Fields with empty-string defaults are optional; callers only need to
    supply ``severity`` and ``title``.  The ``source`` and ``event`` fields
    default to fixed values to simplify webhook integration — downstream
    consumers can rely on them without inspecting caller code.
    """

    source: str = "alertflow"
    event: str = "alert.triaged"
    severity: str
    title: str
    description: str = ""
    ioc: str = ""
    analyst: str = ""
    action: str = ""