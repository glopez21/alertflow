# AlertFlow — Issues & Roadmap

> Last updated: 2026-08-20 | Version: **0.7.0**

---

## Resolved Issues

### Critical Bugs (All Fixed in v0.3.1)

| # | File | Issue | Fix |
|---|------|-------|-----|
| 1 | `live/__main__.py` | `create_ticket_system()` returns wrong class | Uses `TicketManager` |
| 2 | `live/siem_collector.py` | `search()` calls missing `_wait_for_results()` | Implemented `_wait_for_results` + `_parse_result` |
| 3 | `enrichment/hash_lookup.py` | Duplicate `md5` regex branches | Removed duplicate |
| 4 | `live/feed_poller.py` | `recent_reports()` not implemented on any feed | Added `_reports` list + method to all clients |

### Code Quality (All Fixed in v0.3.1)

| # | Issue | Fix |
|---|-------|-----|
| 5-11 | Unused imports across all files | Removed |
| 12-18 | Logic/dead code issues | Fixed |
| 19-23 | `except Exception: pass` silenced errors | Replaced with `logger.warning()` |
| 24 | `list_alerts` return type | `list` → `list[dict]` |

### Production Bugs (All Fixed in v0.7.0)

| # | File | Issue | Severity | Fix |
|---|------|-------|----------|-----|
| 37 | `main.py:87` | Inverted triage condition (`"y"` → `"n"` early exit) | Critical | Fixed logic |
| 38 | `main.py:183` | Comment indentation outside `if` block | Critical | Fixed indentation |
| 39 | `api/deps.py` | Thread-unsafe singleton without Lock | Critical | Added `threading.Lock` |
| 40 | `api/app.py` | `asyncio` imported via `__import__` | High | Fixed to `import asyncio` |
| 41 | `api/app.py` | `asyncio.create_task` not awaited | High | Added `CancelledError` guard |
| 42 | `api/models.py` | `StatusUpdate` missing Closed statuses | Medium | Added `Closed - Benign`, `Closed - Responded` |
| 43 | `api/routes.py` | `has_more` not computed | Medium | Added calculation |
| 44 | `auth.py` | No `ALERTFLOW_AUTH_ENABLED` toggle | Medium | Added env var |
| 45 | `auth.py` | No username sanitization | Medium | Added `sanitize_username()` |
| 46 | `db.py` | No thread safety on read methods | High | Added `self._lock` to all read methods |
| 47 | `db.py` | Inconsistent timestamp format | Medium | Extracted `_cutoff()` helper |
| 48 | `db.py` | Raw MySQL rows not parsed | Medium | Added `_parse_mysql_row`/`_parse_mysql_rows` |
| 49 | `enrichment/ip_lookup.py` | No IPv6 guard on `get_geoip` | Low | Added `socket.AF_INET` check |
| 50 | `enrichment/ip_lookup.py` | `get_reverse_dns` no timeout | Low | Added `socket.setdefaulttimeout(5)` |
| 51 | `integrations/adminflow.py` | Unescaped username in URL path | High | Added `_safe_url_path()` |
| 52 | `augur_notifier.py` | `asyncio.run()` in `finally` block | High | Moved to success path only |
| 53 | `augur_notifier.py` | `logger.debug` on failure | Low | Changed to `logger.warning` |
| 54 | `live/siem_collector.py` | SPL injection in queries | High | Regex-validated inputs |
| 55 | `live/ticket_creator.py` | Unreliable `hash()` on dicts | Medium | Replaced with `hashlib.md5` |
| 56 | `live/ticket_creator.py` | `datetime.utcnow()` (deprecated) | Medium | Changed to `datetime.now(timezone.utc)` |
| 57 | `kafka_consumer.py` | Sync DB calls in async context | Medium | Wrapped in `asyncio.to_thread` |
| 58 | `utils.py` | Domain detection matches substrings | Low | Changed `in` to `endswith` |
| 59 | `logging_config.py` | No log level validation | Low | Added `getLevelName` validation |
| 60 | `api/health.py` | Leaks exception details | Medium | Sanitized error message |

---

## Remaining Open Issues

### Architecture / Design (Low Priority)

| # | Area | Issue | Priority |
|---|------|-------|----------|
| 25 | `enrichment/ioc_extract.py` | `extract_hashes` return type should be `dict[str, list[str]]` | Low |
| 27 | `main.py` | `AlertStore.update_status()` parameter naming confusing | Low |
| 28 | Enrichment scripts | Dual CLI support (argparse + typer) duplicated display logic | Medium |
| 30 | `live/feed_poller.py` | Duplicate IOC checking: module-level vs `FeedPoller.check_ioc()` | Medium |
| 31 | `scripts/demo.py` | Hardcoded sample data, doesn't run actual enrichment | Low |
| 32 | `live/feed_poller.py` | Heuristic hash vs IP detection is fragile | Low |

---

## Version History

| Version | Changes |
|---------|---------|
| 0.7.0 | Production: MySQL dual-backend, Kafka consumer, Prometheus metrics, rate limiting, HMAC auth, idempotency, retention, Dockerfile improvements, bug fixes across all modules |
| 0.6.0 | Production-ready API with enrichment, AuthFlow, AdminFlow, ThreatPulse integration |
| 0.5.0 | CLI triage: FP detection, lifecycle management, timeline, notes, dedup |
| 0.4.0 | SQLite storage, REST API, external integrations |
| 0.3.1 | Fixed 4 critical bugs + 18 code quality issues + 100+ lint warnings |
| 0.3.0 | Threat intel: AbuseIPDB, AlienVault OTX, Splunk/Elastic, ticket creation |
| 0.2.0 | Enrichment: IP reputation, IOC extraction, domain lookup, hash lookup |
| 0.1.0 | Core: 5-phase workflow, SQLite storage, alert CRUD |

---

## Ecosystem Map

```
[LogSentry]                     [AlertFlow]                    [ThreatPulse]
  log parser ──alerts──►        triage CLI        ──webhook──►  SOC platform
  detection rules               enrichment                      threat intel
  SIEM export                   ticketing                        incidents
       │                             │                              │
       └──► [Splunk/ES] ◄────────────┘                              │
                                                                     │
                                                             [AdminFlow]
                                                               AD management
                                                               user disable
```
