"""Enrichment endpoint."""

import asyncio

from fastapi import APIRouter, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.models import EnrichRequest, EnrichResponse
from pipeline import enrich_target
from utils import detect_ioc_type

router = APIRouter(prefix="/api/enrich", tags=["enrichment"])
limiter = Limiter(key_func=get_remote_address)


@router.post("", response_model=EnrichResponse)
@limiter.limit("60/minute")
async def enrich(request: Request, body: EnrichRequest):
    target_type = detect_ioc_type(body.target) if not body.target_type else body.target_type

    if target_type == "email":
        target_type = "user"

    result = await asyncio.to_thread(enrich_target, body.target, target_type)

    if target_type == "unknown":
        from enrichment.ioc_extract import extract_iocs
        iocs = extract_iocs(body.target)
        return EnrichResponse(
            target=body.target,
            target_type="unknown",
            checks=iocs,
        )

    return EnrichResponse(
        target=body.target,
        target_type=target_type,
        checks=result.get("checks", {}),
    )
