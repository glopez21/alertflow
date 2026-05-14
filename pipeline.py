"""Integration pipeline: triage → enrich → notify → respond."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from enrichment.ioc_extract import extract_iocs
from enrichment.ip_lookup import enrich_ip
from enrichment.domain_lookup import enrich_domain
from enrichment.hash_lookup import enrich_hash
from enrichment.user_lookup import enrich_user
from utils import detect_ioc_type

logger = logging.getLogger(__name__)


def auto_detect_ioc_type(target: str) -> str:
    return detect_ioc_type(target)


def enrich_target(target: str, target_type: str | None = None) -> dict:
    """Enrich a single IOC using the appropriate enrichment module."""
    ioc_type = target_type or detect_ioc_type(target)

    if ioc_type == "ip":
        return {"type": "ip", **enrich_ip(target)}
    elif ioc_type == "domain":
        return {"type": "domain", **enrich_domain(target)}
    elif ioc_type == "hash":
        return {"type": "hash", **enrich_hash(target)}
    elif ioc_type == "email" or ioc_type == "user":
        username = target.split("@")[0] if "@" in target else target
        return {"type": "user", **enrich_user(username)}
    else:
        return {"type": "unknown", "target": target}


def extract_and_enrich(raw_text: str, max_workers: int = 4) -> dict:
    """Extract all IOCs from text and enrich each one in parallel."""
    iocs = extract_iocs(raw_text)
    enrichment_results = {}

    targets = []
    for ip in iocs.get("ips", []):
        targets.append((f"ip_{ip}", ip, "ip"))
    for domain in iocs.get("domains", []):
        targets.append((f"domain_{domain}", domain, "domain"))
    for hash_type in ("md5", "sha1", "sha256"):
        for h in iocs.get("hashes", {}).get(hash_type, []):
            targets.append((f"hash_{h[:12]}", h, "hash"))
    for email in iocs.get("emails", []):
        targets.append((f"email_{email}", email, "email"))

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
                logger.warning("Enrichment failed for %s: %s", key, e)

    return {"iocs": iocs, "enrichment": enrichment_results}


def push_to_threatpulse(
    alert_data: dict,
    enrichment: dict,
    base_url: str,
    api_key: str = "",
) -> dict | None:
    """Send triaged alert data to ThreatPulse via webhook."""
    try:
        from integrations.threatpulse import ThreatPulseClient
        from models import ThreatPulseWebhookPayload

        with ThreatPulseClient(base_url, api_key) as client:
            severity = alert_data.get("severity", "P3")
            title = alert_data.get("title", "Security Alert")

            severity_map = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
            tp_severity = severity_map.get(severity, "medium")

            iocs = enrichment.get("iocs", {})
            all_ips = iocs.get("ips", [])
            all_domains = iocs.get("domains", [])
            all_hashes = []
            for ht in ("md5", "sha1", "sha256"):
                all_hashes.extend(iocs.get("hashes", {}).get(ht, []))
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
    """Disable a compromised user account in AdminFlow."""
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