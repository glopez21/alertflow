"""On-demand IOC enrichment endpoint.

Provides a synchronous-to-async bridge for the enrichment pipeline.  The actual
enrichment work (VirusTotal, AbuseIPDB, etc.) is CPU/IO-bound and runs in a
dedicated thread via ``asyncio.to_thread`` so it never blocks the uvicorn event
loop.

The endpoint also handles the "unknown" IOC type fallback: when the IOC cannot
be classified (e.g. a raw domain that doesn't match known patterns), it falls
back to regex-based IOC extraction from the raw text.
"""

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
    """Enrich an IOC (IP, hash, domain, email, URL) against external threat feeds.

    ``asyncio.to_thread`` offloads the blocking ``enrich_target`` call to a
    thread-pool worker, keeping the async event loop responsive for other
    concurrent requests.  This is necessary because the enrichment libraries
    perform synchronous HTTP requests internally.

    Email targets are remapped to "user" internally to match the enrichment
    pipeline's entity model.
    """
    target_type = detect_ioc_type(body.target) if not body.target_type else body.target_type

    # The enrichment pipeline models email addresses as "user" entities.
    if target_type == "email":
        target_type = "user"

    # Run the blocking enrichment pipeline in a thread to avoid blocking the
    # asyncio event loop (uvicorn serves requests on this loop).
    result = await asyncio.to_thread(enrich_target, body.target, target_type)

    if target_type == "unknown":
        # Fallback: try to extract IOCs from the raw text via regex patterns.
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
