# AlertFlow

**SOC alert triage workflow system with enrichment, live integration, and REST API.**

AlertFlow is a production-ready Tier 1 SOC alert handling system. It implements the 5-phase triage workflow (REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE) with automated IOC enrichment, threat intelligence integration, and a REST API for programmatic access.

---

## Quick Start

```bash
cd projects/alertflow
uv sync

# Run the CLI triage workflow
uv run main.py triage alert.json --enrich --push

# Start the REST API server
uvicorn api.app:app --host 0.0.0.0 --port 8000

# Or use Docker
docker compose up api
```

---

## Features

### CLI Triage Workflow
- Interactive 5-phase triage: REVIEW → VALIDATE → ENRICH → DOCUMENT → ESCALATE
- Automated IOC extraction and enrichment during triage
- Push results to ThreatPulse and disable compromised users via AdminFlow
- Alert lifecycle management: create, list, close, false-positive, delete

### REST API
- Full alert CRUD: `GET/POST/PATCH/DELETE /api/alerts`
- IOC enrichment: `POST /api/enrich`
- Health check: `GET /api/health`
- Prometheus metrics: `GET /metrics`
- Authentication via API key (Bearer token or X-API-Key header)
- Rate limiting per endpoint

### Enrichment Tools
- **IP Lookup**: Reverse DNS, GeoIP, private IP detection (IPv4/IPv6)
- **Domain Lookup**: WHOIS, DNS records, reputation, DGA detection
- **Hash Lookup**: MD5/SHA1/SHA256 type detection, reputation scoring
- **User Lookup**: Account info, activity, group membership, risk scoring
- **IOC Extract**: Automated extraction from raw alert text

### Live Integration
- **SIEM**: Splunk and Elasticsearch alert collectors
- **Ticketing**: Jira and ServiceNow ticket creation
- **Threat Feeds**: VirusTotal, AbuseIPDB, AlienVault OTX polling
- **Kafka**: Real-time alert ingestion from message bus

### Infrastructure
- **Database**: SQLite (dev/test) or MySQL (production)
- **Logging**: Structured JSON logging with request tracking
- **Metrics**: Prometheus + OpenTelemetry/Jaeger tracing support
- **Auth**: HMAC-compliant API key authentication with audit trail
- **Docker**: Multi-stage build, health checks, resource limits

---

## Usage

### Enrichment
```bash
# IP investigation
uv run -m enrichment ip 192.168.1.100

# Domain reputation
uv run -m enrichment domain suspicious-domain.xyz

# Hash check
uv run -m enrichment hash aadea647deadbeef...

# User context
uv run -m enrichment user admin

# Auto-detect IOC type
uv run -m enrichment all 192.168.1.1
```

### CLI Commands
```bash
# Triage an alert file with enrichment and ThreatPulse push
uv run main.py triage alert.json --enrich --push --tp-url https://tp.example.com

# Create an alert
uv run main.py create "Suspicious RDP Login" --severity P2 --source splunk

# List alerts
uv run main.py list
uv run main.py list "Open"

# Close an alert
uv run main.py close 1 --analyst "jsmith" --reason "Authorized admin activity"

# Mark as false positive
uv run main.py fp 1 --reason "Vulnerability scanner"

# Add a note
uv run main.py note 1 --note "Checked AD logs — user was on PTO"

# View alert timeline
uv run main.py timeline 1

# Delete an alert
uv run main.py delete 1

# Migrate from legacy JSON storage
uv run main.py migrate alerts.json
```

### REST API
```bash
# Create alert
curl -X POST http://localhost:8000/api/alerts \
  -H "Content-Type: application/json" \
  -d '{"title": "Suspicious Login", "severity": "P2", "source": "splunk"}'

# List alerts
curl http://localhost:8000/api/alerts?status=Open&limit=10

# Enrich an IOC
curl -X POST http://localhost:8000/api/enrich \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# Health check
curl http://localhost:8000/api/health

# Metrics
curl http://localhost:8000/metrics
```

### Live Integration
```bash
# Fetch recent SIEM alerts
uv run -m live siem --hours 1 --limit 10

# Check IOC against threat feeds
uv run -m live check 192.168.1.1 --feeds abuseipdb,virustotal

# Create ticket
uv run -m live ticket "Alert title" --priority critical
```

### Docker
```bash
# Build and run API server
docker compose up api

# Run CLI commands
docker compose run cli triage alert.json --enrich --push
docker compose run cli list
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERTFLOW_DB` | `alertflow.db` | SQLite database path |
| `ALERTFLOW_MYSQL_URL` | _(empty)_ | MySQL connection URL (overrides SQLite) |
| `ALERTFLOW_API_KEY` | _(empty)_ | API key for authentication (empty = disabled) |
| `ALERTFLOW_AUTH_ENABLED` | `true` | Enable/disable API authentication |
| `ALERTFLOW_CORS_ORIGINS` | `*` | Comma-separated CORS origins |
| `ALERTFLOW_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `ALERTFLOW_LOG_FORMAT` | `json` | Log format: `json` or `console` |
| `ALERTFLOW_RATE_LIMIT` | `60/minute` | API rate limit |
| `ALERTFLOW_RETENTION_DAYS` | `0` | Auto-delete closed alerts (0 = disabled) |
| `ALERTFLOW_KAFKA_ENABLED` | `false` | Enable Kafka consumer |
| `ALERTFLOW_KAFKA_TOPIC` | `logsentry-to-alertflow` | Kafka topic to consume |
| `ALERTFLOW_KAFKA_GROUP` | `alertflow-consumers` | Kafka consumer group |
| `KAFKA_BROKER` | `kafka:9092` | Kafka broker address |
| `THREATPULSE_URL` | _(empty)_ | ThreatPulse base URL |
| `THREATPULSE_API_KEY` | _(empty)_ | ThreatPulse API key |
| `ADMINFLOW_URL` | _(empty)_ | AdminFlow base URL |
| `ADMINFLOW_API_KEY` | _(empty)_ | AdminFlow API key |
| `AUGUR_URL` | _(empty)_ | Augur hub URL |

### MySQL Configuration
```bash
export ALERTFLOW_MYSQL_URL=mysql://alertflow_user:password@localhost:3306/alertflow
```

---

## Workflow

```
┌───────────────────────────────────────────────────────────┐
│                    AlertFlow                              │
├─────────────┬─────────────┬─────────────┬─────────────────┤
│   REVIEW    │   VALIDATE  │   ENRICH    │   DOCUMENT      │
│ 2 minutes   │   5 minutes │ 10 minutes  │   5 minutes     │
├─────────────┴─────────────┴─────────────┴─────────────────┤
│  - Confirm    - Check FP    - IP/Domain   - Timeline      │
│  - Severity   - Allowlist   - Hash/User   - IOCs          │
│  - Categorize - Baseline   - Threat Feeds- Evidence       │
└───────────────────────────────────────────────────────────┘
                          │
                    ┌─────┴────┐
                    │ ESCALATE │
                    │  Close   │
                    └──────────┘
```

---

## Architecture

```
Logs ──► [LogSentry] ──detections──► [AlertFlow] ──triaged alerts──► [ThreatPulse]
          (log parser      (triage CLI,        (incidents, IOCs,
          + detection)      REST API)           notifications)
                                    │
                                    │ user disable / lock
                                    ▼
                               [AdminFlow]
                           (AD automation)
```

---

## Escalation Criteria

| Severity | Definition | Example |
|----------|------------|---------|
| **P1** | Active compromise | Malware, lateral movement, data exfil |
| **P2** | Suspected compromise | Failed logins burst, privilege escalation |
| **P3** | Suspicious activity | Single failed login, policy violation |
| **P4** | Informational | Baseline deviation, audit event |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `pydantic` | Request/response validation |
| `typer` | CLI framework |
| `rich` | Terminal UI |
| `httpx` | HTTP client |
| `slowapi` | API rate limiting |
| `prometheus-client` | Metrics |
| `prometheus-fastapi-instrumentator` | API metrics |
| `structlog` | Structured logging |
| `aiomysql` | MySQL async driver |
| `aiokafka` | Kafka consumer |
| `n3xuslib` | n3xusDB integration |

---

## Project Structure

```
alertflow/
├── main.py                    # CLI entry point
├── pipeline.py                # Triage pipeline (enrich → notify → respond)
├── db.py                      # Alert storage (SQLite/MySQL)
├── utils.py                   # Shared utilities
├── models.py                  # Top-level Pydantic models
├── auth.py                    # API authentication middleware
├── logging_config.py          # Structured logging setup
├── kafka_consumer.py          # Kafka alert ingestion
├── augur_notifier.py          # Augur/n3xusDB push
├── api/                       # FastAPI REST API
│   ├── app.py                 # Application factory + middleware
│   ├── routes.py              # Alert CRUD endpoints
│   ├── enrich.py              # Enrichment endpoint
│   ├── models.py              # Request/response models
│   ├── health.py              # Health check
│   └── deps.py                # Dependency injection
├── enrichment/                # IOC enrichment tools
│   ├── ip_lookup.py
│   ├── domain_lookup.py
│   ├── hash_lookup.py
│   ├── user_lookup.py
│   ├── ioc_extract.py
│   └── __main__.py            # Unified CLI
├── integrations/              # External system clients
│   ├── threatpulse.py
│   └── adminflow.py
├── live/                      # Live integration modules
│   ├── siem_collector.py
│   ├── ticket_creator.py
│   ├── feed_poller.py
│   └── __main__.py
├── tests/                     # 148 tests
├── runbooks/                  # Alert handling procedures
├── templates/                 # Ticket templates
├── checklists/                # Quick references
├── Dockerfile                 # Multi-stage build
├── docker-compose.yml         # API + CLI services
├── pyproject.toml             # Dependencies & metadata
└── .env.example               # Configuration reference
```

---

## Testing

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=.

# Lint
uv run ruff check .
```

---

## License

MIT
