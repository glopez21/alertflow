"""Integration pipeline: triage -> enrich -> notify -> respond.

This module is the central nervous system of the AlertFlow enrichment
and response workflow.  It orchestrates three major phases:

1. **Extract** -- Pull IOCs (IPs, domains, hashes, emails) from raw alert
   text via ``enrichment.ioc_extract``.
2. **Enrich** -- Look up each IOC through the appropriate external service
   (DNS, VirusTotal, user directory) in parallel, protected by per-service
   circuit breakers.
3. **Respond** -- Push triaged results to ThreatPulse and/or disable
   compromised accounts in AdminFlow.

Threading model
---------------
``extract_and_enrich`` fans out enrichment calls across a
``ThreadPoolExecutor`` (default 4 workers).  Each enrichment call is
routed through a service-specific ``CircuitBreaker`` so that a degraded
downstream does not exhaust thread-pool capacity.

Circuit breaker mapping
-----------------------
- IP / domain lookups  -> ``dns`` breaker
- Hash lookups         -> ``virustotal`` breaker
- Everything else      -> ``enrichment`` default breaker
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from enrichment.ioc_extract import extract_iocs
from enrichment.ip_lookup import enrich_ip
from enrichment.domain_lookup import enrich_domain
from enrichment.hash_lookup import enrich_hash
from enrichment.user_lookup import enrich_user
from resilience import CircuitOpenError, get_breaker, call_with_breaker
from utils import detect_ioc_type

logger = logging.getLogger(__name__)

# Per-service breakers -- shared across all pipeline calls.
# Each breaker trips after 3 consecutive failures and waits 30s before
# allowing a probe request.  Separate breakers prevent a DNS outage from
# blocking VirusTotal lookups and vice-versa.
_dns_breaker = get_breaker("dns", failure_threshold=3, recovery_timeout=30.0)
_vt_breaker = get_breaker("virustotal", failure_threshold=3, recovery_timeout=30.0)
_default_breaker = get_breaker("enrichment", failure_threshold=3, recovery_timeout=30.0)

# Map IOC types to the breaker that protects the relevant external API.
_BREAKER_MAP = {
    "ip": _dns_breaker,
    "domain": _dns_breaker,
    "hash": _vt_breaker,
}


def auto_detect_ioc_type(target: str) -> str:
    """Detect the IOC type of *target* by delegating to ``utils.detect_ioc_type``.

    Thin wrapper kept for backward compatibility; callers that only need
    type detection can import this directly.
    """
    return detect_ioc_type(target)


def _enrich_dispatch(target: str, ioc_type: str) -> dict:
    """Dispatch *target* to the correct enrichment backend.

    This function intentionally contains **no** retry or circuit-breaker
    logic; that layer is handled by ``enrich_target`` which calls this
    function through ``call_with_breaker``.

    Args:
        target: The raw IOC string (IP, domain, hash, email, etc.).
        ioc_type: One of ``"ip"``, ``"domain"``, ``"hash"``, ``"email"``,
                  ``"user"``, or ``"unknown"``.

    Returns:
        A dict with a ``"type"`` key and enrichment-specific fields.
    """
    if ioc_type == "ip":
        return {"type": "ip", **enrich_ip(target)}
    elif ioc_type == "domain":
        return {"type": "domain", **enrich_domain(target)}
    elif ioc_type == "hash":
        return {"type": "hash", **enrich_hash(target)}
    elif ioc_type in ("email", "user"):
        # Strip the domain portion so the user-lookup receives a bare
        # username regardless of whether a full email was provided.
        username = target.split("@")[0] if "@" in target else target
        return {"type": "user", **enrich_user(username)}
    else:
        return {"type": "unknown", "target": target}


def enrich_target(target: str, target_type: str | None = None) -> dict:
    """Enrich a single IOC with circuit breaker and retry isolation.

    Automatically detects the IOC type (or accepts a caller-provided type)
    and selects the appropriate per-service circuit breaker.

    Args:
        target: The IOC value to enrich.
        target_type: Optional pre-detected type string.  When ``None``,
                     ``detect_ioc_type`` is called to infer the type.

    Returns:
        A dict containing enrichment results.  If the circuit is open or
        the call fails, the dict includes an ``"error"`` key so callers
        can degrade gracefully rather than crashing.
    """
    ioc_type = target_type or detect_ioc_type(target)
    # Select the breaker that protects the relevant external API;
    # fall back to the generic enrichment breaker for unknown types.
    breaker = _BREAKER_MAP.get(ioc_type, _default_breaker)

    try:
        return call_with_breaker(
            breaker,
            _enrich_dispatch,
            target,
            ioc_type,
            retries=3,
            backoff_base=0.5,  # delays: 0.5s, 1.0s, 2.0s
        )
    except CircuitOpenError as e:
        logger.warning("enrichment.circuit_open target=%s type=%s error=%s", target, ioc_type, e)
        return {"type": ioc_type, "target": target, "error": str(e), "circuit_open": True}
    except Exception as e:
        logger.warning("enrichment.failed target=%s type=%s error=%s", target, ioc_type, e)
        return {"type": ioc_type, "target": target, "error": str(e)}


def extract_and_enrich(raw_text: str, max_workers: int = 4) -> dict:
    """Extract all IOCs from *raw_text* and enrich each one in parallel.

    This is the main entry point for the enrichment pipeline.  It:

    1. Calls ``extract_iocs`` to parse IOCs from the raw alert text.
    2. Builds a list of ``(key, target, type)`` tuples, one per IOC.
    3. Submits each enrichment call to a ``ThreadPoolExecutor`` so that
       independent lookups (e.g. multiple IPs) run concurrently.
    4. Collects results keyed by a stable identifier (e.g. ``"ip_1.2.3.4"``).

    Args:
        raw_text: The raw alert body / description to scan for IOCs.
        max_workers: Maximum parallel enrichment threads (default 4).

    Returns:
        A dict with two keys:
        - ``"iocs"``: The raw extracted IOC dict from ``extract_iocs``.
        - ``"enrichment"``: A dict mapping IOC keys to their enrichment
          results (or error dicts on failure).
    """
    iocs = extract_iocs(raw_text)
    enrichment_results = {}

    # Flatten the nested IOC dict into a uniform list of work items.
    # Each tuple is (stable_key, ioc_value, ioc_type).
    targets = []
    for ip in iocs.get("ips", []):
        targets.append((f"ip_{ip}", ip, "ip"))
    for domain in iocs.get("domains", []):
        targets.append((f"domain_{domain}", domain, "domain"))
    for hash_type in ("md5", "sha1", "sha256"):
        for h in iocs.get("hashes", {}).get(hash_type, []):
            # Truncate the key to keep log / table output readable.
            targets.append((f"hash_{h[:12]}", h, "hash"))
    for email in iocs.get("emails", []):
        targets.append((f"email_{email}", email, "email"))

    # Fan out enrichment calls across the thread pool.  Each call is
    # independently protected by its own circuit breaker.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(enrich_target, target, ttype): key
            for key, target, ttype in targets
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                enrichment_results[key] = future.result()
            except Exception as e:
                # Should rarely happen since enrich_target catches its own
                # exceptions; defensive guard against unexpected failures.
                logger.warning("Enrichment failed for %s: %s", key, e)

    return {"iocs": iocs, "enrichment": enrichment_results}


def push_to_threatpulse(
    alert_data: dict,
    enrichment: dict,
    base_url: str,
    api_key: str = "",
) -> dict | None:
    """Send triaged alert data to ThreatPulse via webhook.

    Builds a ``ThreatPulseWebhookPayload`` from the alert and enrichment
    data, maps internal severity levels (P1-P4) to ThreatPulse severity
    strings, and posts the payload through ``ThreatPulseClient``.

    Args:
        alert_data: The alert dict (must include at least ``"title"``
                    and ``"severity"``).
        enrichment: The enrichment dict returned by ``extract_and_enrich``.
        base_url: ThreatPulse API base URL.
        api_key: API key for ThreatPulse authentication.

    Returns:
        The API response dict on success, or ``None`` if the integration
        is unavailable or the push fails (errors are logged, not raised).

    Severity mapping
    ----------------
    P1 -> critical, P2 -> high, P3 -> medium, P4 -> low.
    Unrecognised values default to ``"medium"``.
    """
    try:
        from integrations.threatpulse import ThreatPulseClient
        from models import ThreatPulseWebhookPayload

        with ThreatPulseClient(base_url, api_key) as client:
            severity = alert_data.get("severity", "P3")
            title = alert_data.get("title", "Security Alert")

            # Map internal P-severity to ThreatPulse's severity vocabulary.
            severity_map = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
            tp_severity = severity_map.get(severity, "medium")

            # Flatten all IOC hashes (across hash types) into a single list.
            iocs = enrichment.get("iocs", {})
            all_ips = iocs.get("ips", [])
            all_domains = iocs.get("domains", [])
            all_hashes = []
            for ht in ("md5", "sha1", "sha256"):
                all_hashes.extend(iocs.get("hashes", {}).get(ht, []))
            # Cap the IOC string to avoid overwhelming the webhook payload.
            ioc_str = ", ".join(all_ips + all_domains + all_hashes[:3])

            payload = ThreatPulseWebhookPayload(
                source="alertflow",
                event="alert.triaged",
                severity=tp_severity,
                title=title,
                description=alert_data.get("raw", ""),
                ioc=ioc_str,
                analyst=alert_data.get("analyst", ""),
                action=alert_data.get("status", "triaged"),
            )

            return client.send_webhook(payload)
    except ImportError:
        # httpx is an optional dependency -- degrade gracefully when absent.
        logger.warning("ThreatPulse integration not available (install httpx)")
        return None
    except Exception as e:
        logger.warning("ThreatPulse push failed: %s", e)
        return None


def disable_user_in_adminflow(
    username: str,
    base_url: str,
    api_key: str = "",
) -> dict | None:
    """Disable a compromised user account in AdminFlow.

    This is a response action invoked when an analyst determines a user
    account is compromised during triage.  The AdminFlow client is
    imported lazily so the pipeline remains functional when the integration
    is not installed.

    Args:
        username: The account to disable (bare username, not email).
        base_url: AdminFlow API base URL.
        api_key: API key for AdminFlow authentication.

    Returns:
        The API response dict on success, or ``None`` on failure.
    """
    try:
        from integrations.adminflow import AdminFlowClient

        with AdminFlowClient(base_url, api_key) as client:
            return client.disable_user(username)
    except ImportError:
        logger.warning("AdminFlow integration not available (install httpx)")
        return None
    except Exception as e:
        logger.warning("AdminFlow user disable failed: %s", e)
        return None
