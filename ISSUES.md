# AlertFlow — Issues & Roadmap

> Auto-generated tracking file. Last updated: 2026-05-30

---

## 🔴 Critical Bugs (Fixed in v0.3.1)

| # | File | Issue | Status |
|---|------|-------|--------|
| ~~1~~ | `live/__main__.py:165` | `create_ticket_system()` returns `JiraCreator`/`ServiceNowCreator` — neither has `create_from_alert()` method. `AttributeError` at runtime. | **FIXED** — uses `TicketManager` instead |
| ~~2~~ | `live/siem_collector.py:82-83` | `SplunkCollector.search()` calls `self._wait_for_results(sid)` which doesn't exist. Silently falls back to sample data. | **FIXED** — implemented `_wait_for_results` + `_parse_result` |
| ~~3~~ | `enrichment/hash_lookup.py:32-35` | `detect_hash_type()` has duplicate `md5` regex branches (same 32-char hex pattern twice). Dead code. | **FIXED** — removed duplicate |
| ~~4~~ | `live/feed_poller.py:223-232` | `FeedPoller.get_high_confidence()` calls `feed.recent_reports()` — no feed class implements this. Returns empty. | **FIXED** — added `_reports` list + `recent_reports()` to all 3 feed clients |

---

## 🟡 Medium Issues (Code Quality) ✅ Phase 2 Complete

### Unused Imports (All Fixed)

| # | File | Fix |
|---|------|-----|
| ~~5-11~~ | All files | **FIXED** — removed unused `subprocess`, `datetime`, `os`, `Optional`, `Any`, `sys`, `Path`, `json`, `timedelta`, `FeedConfig`, `SIEMConfig` imports. Removed redundant `json` re-imports. |

### Logic / Dead Code (All Fixed)

| # | File | Fix |
|---|------|-----|
| ~~12~~ | `enrichment/__main__.py:73-91` | **FIXED** — `hash` command now respects `--json` flag |
| ~~13~~ | `enrichment/__main__.py:136-146` | **FIXED** — `all` command now handles `email` and `url` types |
| ~~14~~ | `enrichment/ip_lookup.py:54-55` | **FIXED** — removed duplicate `elif second == 168` |
| ~~15~~ | `enrichment/user_lookup.py:161-167` | **FIXED** — password aging now computes actual days since last change |
| ~~16~~ | `enrichment/domain_lookup.py:46-55` | **FIXED** — added `warnings.warn()` when `dnspython` is missing |
| ~~17~~ | `live/ticket_creator.py:138,146` | **FIXED** — removed redundant initial `priority` assignment |
| ~~18~~ | `live/siem_collector.py` | **NOTED** — two separate sample functions serve different classes; kept as-is |

### Error Handling (All Fixed)

| # | File | Fix |
|---|------|-----|
| ~~19-21~~ | All API clients | **FIXED** — all `except Exception: pass` replaced with `logger.warning()` + error message |
| ~~22~~ | `main.py:95` | **FIXED** — split into `FileNotFoundError` and `json.JSONDecodeError` |
| ~~23~~ | `enrichment/domain_lookup.py` | **FIXED** — added `warnings.warn()` for missing `dnspython` |

### Type Hints

| # | File | Issue | Status |
|---|------|-------|--------|
| ~~24~~ | `main.py:80` | `list_alerts` return type | **FIXED** — `list` → `list[dict]` |
| 25 | `enrichment/ioc_extract.py:46-48` | `extract_hashes` return type is `dict` — should be `dict[str, list[str]]` | Open

---

## 🟢 Improvement Opportunities

### Architecture / Design

| # | Area | Issue | Priority |
|---|------|-------|----------|
| 26 | `main.py` | `store` is a module-level mutable singleton — problematic in import/reload contexts | Low |
| 27 | `main.py` | `AlertStore.update_status()` parameter naming confusing: `close()` passes `reason` as `fp_reason` | Low |
| 28 | Enrichment scripts | Dual CLI support (argparse standalone + typer via `__main__.py`) — duplicated display logic | Medium |
| 29 | `enrichment/__main__.py` | `domain` command truncates lists to 3 items, but `ip` command doesn't handle list values | Low |
| 30 | `live/feed_poller.py` | Duplicate IOC checking logic: module-level `check_ioc_with_feeds()` vs `FeedPoller.check_ioc()` | Medium |
| 31 | `scripts/demo.py` | Hardcoded sample data — doesn't import/execute actual enrichment functions | Low |
| 32 | `live/feed_poller.py:244` | Heuristic `if "." in ioc and len(ioc) > 40` to distinguish hash from IP is fragile | Low |
| 33 | `pyproject.toml` | `live` extra only lists `httpx` which is already a main dependency — redundant | Low |
| 34 | `README.md` | Mentions `requests` in deps table but only `httpx` is in `pyproject.toml` | Low |
| 35 | `README.md` | Mentions `docs/INTEGRATION.md` but directory doesn't exist | Low |

### Testing

| # | Area | Issue | Priority |
|---|------|-------|----------|
| ~~36~~ | Entire project | **No tests existed** — now 148 tests across 8 test files | **FIXED** |

---

## 📋 Roadmap

### Phase 2: Code Quality Cleanup ✅ Complete
- [x] Remove all unused imports
- [x] Fix `hash` command `--json` flag
- [x] Fix `all` command handling `email`/`url` types
- [x] Fix `ip_lookup.py` duplicate `elif`
- [x] Fix `user_lookup.py` dead password aging logic
- [x] Un-silence error handling (logging instead of `except Exception: pass`)
- [x] Deduplicate `check_ioc_with_feeds()` — delegates to `FeedPoller.check_ioc()`
- [x] Remove redundant `live` extra in `pyproject.toml`
- [x] Fix README inconsistencies (remove `requests`, fix stale docs reference)
- [x] Fix f-strings without placeholders (ruff F541)
- [x] Fix unused variable `notes` in `main.py`
- [x] Bump version to 0.3.1
- [x] Bump version to 0.4.0 (SQLite)
- [x] Bump version to 0.5.0 (API + integrations + pipeline)
- [x] Fix remaining ruff lint warnings (unused imports, f-strings, unused vars)

### Phase 3: Tests ✅ Complete
- [x] Add `pytest` dev dependency
- [x] Unit tests for `AlertStore` — 12 tests (CRUD, persistence, edge cases)
- [x] Unit tests for hash lookup — 11 tests (type detection, reputation, VT, file info)
- [x] Unit tests for IOC extraction — 16 tests (IPs, domains, hashes, URLs, emails, file paths, accounts)
- [x] Unit tests for IP lookup — 12 tests (private IP, enrichment, reverse DNS)
- [x] Unit tests for domain lookup — 9 tests (WHOIS, reputation, suspicious patterns, enrichment)
- [x] Unit tests for user lookup — 11 tests (account info, activity, groups, risk scoring)
- [x] Unit tests for TicketManager — 6 tests (Jira, ServiceNow, enrichment, unknown system)
- [x] **Bug discovered**: benign hash prefix was 7 chars vs 8 chars — **fixed**
- [x] **Bug discovered**: Windows path regex only matched single segment — **fixed**
- [x] **Bug discovered**: `JiraCreator`/`ServiceNowCreator` missing `_sample_ticket` method — **fixed**

**Total: 91 tests, all passing**

### Phase 4: Database ✅ Complete
- [x] Replace JSON file storage with SQLite (`sqlite3` stdlib — no new deps)
- [x] Schema: `alerts` table with all fields + JSON-serialized notes/enrichment
- [x] `migrate` CLI command to import from `alerts.json`
- [x] Thread-safe with `threading.Lock`
- [x] WAL journal mode for concurrent read performance
- [x] Tests: 19 total (12 CRUD + 3 migration + 4 new: add_note, multiple notes, both analyst+fp, migration edge case)

### Phase 5: REST API + Integration Layer ✅ Complete
- [x] FastAPI server (`api/app.py`) with endpoints:
  - `GET /api/health` — health check
  - `GET /api/alerts` — list/filter alerts
  - `POST /api/alerts` — create alert (receives from LogSentry)
  - `GET /api/alerts/{id}` — get alert detail
  - `PATCH /api/alerts/{id}` — update status
  - `POST /api/alerts/{id}/notes` — add timeline entry
  - `POST /api/enrich` — enrichment endpoint (IP, domain, hash, user)
- [x] Pydantic models for request/response validation
- [x] `ThreatPulseClient` — webhook sender, IOC lookup, incident creation
- [x] `AdminFlowClient` — user disable/enable, password reset, privileged accounts
- [x] 14 API tests (health, CRUD, enrichment)
- [x] Thread-safe SQLite (`check_same_thread=False`)

### Phase 6: Integration Pipeline ✅ Complete
- [x] Wire `triage` CLI command → enrichment modules via `pipeline.py`
- [x] Auto-extract and enrich IOCs during triage (`extract_and_enrich()`)
- [x] Push triage results to ThreatPulse via `POST /api/v1/webhooks`
- [x] Push user disable actions to AdminFlow on confirmed compromise
- [x] CLI flags: `--enrich/--no-enrich`, `--push/--no-push`, `--disable-user`, `--tp-url`, `--af-url`
- [x] `ALERTFLOW_DB` env var for configurable DB path
- [x] Dockerfile + docker-compose (API server + CLI)
- [x] GitHub Actions CI workflow (ruff lint, pytest, Docker build)
- [x] 24 pipeline tests (auto-detect, enrich, ThreatPulse push, AdminFlow disable)

### Phase 7: Hardening & Optimization ✅ Complete
- [x] **Thread-safe DB**: `_get_conn()` uses `RLock` (reentrant) — fixes deadlock from nested lock calls
- [x] **App shutdown lifecycle**: FastAPI lifespan event closes `AlertStore` connection on shutdown
- [x] **Consolidated SQL**: `update_status()` now uses single UPDATE with field-level merge instead of 4 branches
- [x] **Enrichment persistence**: triage command saves `enrichment_data` to DB via `update_enrichment()`
- [x] **New DB methods**: `update_enrichment()`, `delete_alert()`, `count_alerts()`, `list_alerts()` returns `(alerts, total)` with pagination
- [x] **New API endpoints**: `DELETE /api/alerts/{id}`, `PATCH /api/alerts/{id}/enrichment`, pagination (`limit`/`offset`)
- [x] **API auth**: `ALERTFLOW_API_KEY` env var — Bearer token or X-API-Key header (empty = disabled)
- [x] **CORS**: `ALERTFLOW_CORS_ORIGINS` env var (default `*`)
- [x] **Input validation**: `AlertCreate.severity` uses `Literal["P1","P2","P3","P4"]`, field length limits
- [x] **Context managers**: `ThreatPulseClient` and `AdminFlowClient` support `with` statement
- [x] **Pipeline clients**: `push_to_threatpulse` and `disable_user_in_adminflow` use context managers
- [x] **CLI env vars**: `--tp-url`/`--tp-key`/`--af-url`/`--af-key` read from `THREATPULSE_URL`/`THREATPULSE_API_KEY`/`ADMINFLOW_URL`/`ADMINFLOW_API_KEY`
- [x] 148 tests, all passing

### Phase 7: Hardening & Optimization ✅ Complete
- [x] Thread-safe `AlertStore` — `_get_conn()` under RLock, `close()` under lock
- [x] FastAPI lifespan — DB connection closed on shutdown
- [x] Consolidated `update_status` from 4 SQL branches to 1 (preserves existing fields)
- [x] Enrichment data persisted to DB — `add_alert(enrichment=...)`, `update_enrichment()`
- [x] `PATCH /api/alerts/{id}/enrichment` — update enrichment via API
- [x] `DELETE /api/alerts/{id}` — delete alert endpoint
- [x] Pagination — `list_alerts(limit, offset)` returns `(alerts, total)`, API returns `limit`/`offset`
- [x] API key auth — `ALERTFLOW_API_KEY` env var, `Authorization: Bearer` or `X-API-Key` header
- [x] CORS middleware — configurable via `ALERTFLOW_CORS_ORIGINS`
- [x] Input validation — `severity: Literal["P1","P2","P3","P4"]`, max_length on strings
- [x] Context managers — `ThreatPulseClient`/`AdminFlowClient` support `with` statement
- [x] Pipeline uses `with Client(...)` instead of manual `.close()`
- [x] CLI env var support — `--tp-url`/`--tp-key`/`--af-url`/`--af-key` read from env vars
- [x] `delete` CLI command
- [x] `count_alerts()` method on AlertStore
- [x] `db.py` version bumps to v0.5.0 (API, health)
- [x] 148 tests, all passing

---

## 🏗 Cross-Project Integration

### Ecosystem Map

```
[LogSentry]                     [AlertFlow]                    [ThreatPulse]
  log parser ──alerts──►        triage CLI        ──webhook──►  SOC platform
  detection rules               enrichment                      threat intel
  SIEM export                   ticketing                        incidents
       │                             │                              │
       │                             │                              │
       └──► [Splunk/ES] ◄────────────┘                              │
                                                                    │
                                                            [AdminFlow]
                                                              AD management
                                                              user disable
```

### LogSentry ↔ AlertFlow
- LogSentry has `AlertFlowAlerter` class that POSTs detections to AlertFlow
- **Done**: AlertFlow REST API accepts alerts at `POST /api/alerts`

### AlertFlow ↔ ThreatPulse
- ThreatPulse has `POST /api/v1/webhooks` for receiving alerts
- ThreatPulse has `GET /api/v1/enrich/{ioc}` for IOC enrichment lookups
- **Done**: AlertFlow `ThreatPulseClient` sends webhooks + `pipeline.push_to_threatpulse()`

### AlertFlow ↔ AdminFlow
- AdminFlow has `PUT /api/users/{username}/disable` for disabling AD accounts
- **Done**: AlertFlow `AdminFlowClient` + `pipeline.disable_user_in_adminflow()`

### Shared Infrastructure Ideas
- Unified Redis pub/sub channel for real-time alert distribution
- Shared PostgreSQL for cross-project querying
- Common Python SDK (`s3cIntegrate`) for all tools
