"""Alert storage — SQLAlchemy ORM with SQLite (dev) and MySQL (production).

Provides the ``AlertStore`` class which wraps a SQLAlchemy engine and exposes
CRUD operations for the ``alerts`` table.  In development the store uses a
local SQLite file with WAL journaling; in production it connects to MySQL via
the ``ALERTFLOW_MYSQL_URL`` environment variable.

Thread safety
-------------
All public methods acquire an ``RLock`` before touching the session to allow
concurrent FastAPI request handlers (which run in a thread-pool for sync
endpoints) to safely share a single ``AlertStore`` instance.  Sessions are
created per-call and closed immediately (context-manager pattern) to avoid
connection leaks.

WAL mode (SQLite only)
----------------------
Write-Ahead Logging is enabled on every new SQLite connection via a
``"connect"`` event listener.  WAL allows concurrent readers while a write is
in-progress and avoids the ``database is locked`` errors that plague the
default rollback journal under multi-threaded access.
"""

import json
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import Session, sessionmaker, DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ORM models in this application."""
    pass


class AlertRow(Base):
    """ORM mapping for the ``alerts`` table.

    Stores triage metadata for a single security alert.  The ``enrichment``
    and ``notes`` columns use JSON-encoded ``Text`` fields rather than
    relational sub-tables to keep the schema flat and migration-friendly for
    the SQLite development backend.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(10), nullable=False)
    source = Column(String(100), nullable=False)
    ioc = Column(String(500), default="")
    status = Column(String(50), default="Open")
    created_at = Column(String(50), nullable=False)
    updated_at = Column(String(50), nullable=False)
    analyst = Column(String(100), default="")
    fp_reason = Column(String(1000), default="")
    # Stored as a JSON-encoded object; deserialized on read by _row_to_dict.
    enrichment = Column(Text, default="{}")
    # Stored as a JSON-encoded array of note objects; appended to in add_note().
    notes = Column(Text, default="[]")


def _row_to_dict(row: AlertRow) -> dict:
    """Convert an ``AlertRow`` ORM instance to a plain dictionary.

    Handles ``None`` defaults for nullable string columns and deserializes
    the JSON-encoded ``enrichment`` and ``notes`` columns.  The resulting
    dict shape matches the API response schema so callers don't need to
    know about the ORM layer.

    Args:
        row: A hydrated ``AlertRow`` instance.

    Returns:
        Dictionary with all alert fields; ``enrichment`` is a ``dict`` and
        ``notes`` is a ``list``.
    """
    return {
        "id": row.id,
        "title": row.title,
        "severity": row.severity,
        "source": row.source,
        "ioc": row.ioc or "",
        "status": row.status,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "analyst": row.analyst or "",
        "fp_reason": row.fp_reason or "",
        "enrichment": json.loads(row.enrichment) if row.enrichment else {},
        "notes": json.loads(row.notes) if row.notes else [],
    }


class AlertStore:
    """Thread-safe alert persistence layer backed by SQLAlchemy.

    Supports two backends selected at construction time:

    * **SQLite** (default) — file-based, zero-config, suitable for local dev.
      The database path can be set via the ``db_path`` argument or the
      ``ALERTFLOW_DB`` environment variable (defaults to ``alertflow.db``).
    * **MySQL** — activated by passing ``mysql_url``.  The URL is forwarded
      directly to ``create_engine`` so it may contain pool settings.

    All public methods are guarded by a re-entrant lock (``threading.RLock``)
    so that multiple FastAPI worker threads can safely share a single store
    instance.  Sessions are scoped to individual method calls and closed in a
    ``with`` block to guarantee connection release even on exceptions.
    """

    def __init__(self, db_path: str | None = None, *, mysql_url: str | None = None):
        """Initialise the store, create tables if they don't exist.

        Args:
            db_path: Filesystem path for the SQLite database file.  Ignored
                when ``mysql_url`` is provided.  Falls back to the
                ``ALERTFLOW_DB`` environment variable, then ``alertflow.db``.
            mysql_url: Full SQLAlchemy connection URL for MySQL (e.g.
                ``mysql+pymysql://user:pass@host/db``).  When provided the
                SQLite path is ignored entirely.
        """
        self._lock = threading.RLock()

        if mysql_url:
            url = mysql_url
        else:
            if db_path is None:
                db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
            self.db_path = Path(db_path)
            url = f"sqlite:///{self.db_path}"

        self._engine = create_engine(
            url,
            echo=False,
            # pool_pre_ping verifies connections are alive before use,
            # preventing stale-connection errors after idle periods.
            pool_pre_ping=True,
            # SQLite is not safe for cross-thread connections by default;
            # we enforce safety at the application level via RLock instead.
            connect_args={"check_same_thread": False} if "sqlite" in url else {},
        )

        if "sqlite" in url:
            # Enable WAL journaling and foreign-key enforcement for every
            # new connection.  WAL allows concurrent reads during writes,
            # drastically reducing "database is locked" errors under load.
            @event.listens_for(self._engine, "connect")
            def _set_sqlite_pragma(dbapi_conn, _):
                dbapi_conn.execute("PRAGMA journal_mode=WAL")
                dbapi_conn.execute("PRAGMA foreign_keys=ON")

        # create_all is idempotent — safe to call on every startup.
        Base.metadata.create_all(self._engine)
        self._SessionFactory = sessionmaker(bind=self._engine)
        self._initialized = True

    def _session(self) -> Session:
        """Create a short-lived ORM session bound to this store's engine."""
        return self._SessionFactory()

    def _now(self) -> str:
        """Return the current UTC time as an ISO 8601 ``Z``-suffixed string."""
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _cutoff(self, seconds: int = 0, days: int = 0) -> str:
        """Return a UTC timestamp offset into the past, formatted identically to ``_now()``.

        Used to build ``WHERE`` clauses for time-range queries (e.g.
        duplicate detection, old-alert cleanup).
        """
        dt = datetime.now(timezone.utc) - timedelta(seconds=seconds, days=days)
        return dt.isoformat().replace("+00:00", "Z")

    def add_alert(self, title: str, severity: str, source: str, ioc: str = "", enrichment: dict | None = None) -> dict:
        """Insert a new alert and return the persisted record as a dict.

        The new alert always starts with ``status="Open"``.  The ``enrichment``
        dict (if provided) is JSON-serialised into the ``enrichment`` column.

        Args:
            title: Short alert heading.
            severity: One of the severity labels (e.g. ``"Critical"``, ``"High"``).
            source: Identifier of the originating system.
            ioc: Optional indicator of compromise associated with the alert.
            enrichment: Optional dict of enrichment data (IP intel, hashes, etc.).

        Returns:
            The newly created alert as a plain dict (includes auto-generated
            ``id`` and timestamps).
        """
        now = self._now()
        with self._lock:
            with self._session() as session:
                alert = AlertRow(
                    title=title,
                    severity=severity,
                    source=source,
                    ioc=ioc,
                    status="Open",
                    created_at=now,
                    updated_at=now,
                    enrichment=json.dumps(enrichment) if enrichment else "{}",
                )
                session.add(alert)
                session.commit()
                # Refresh to populate the auto-generated ``id``.
                session.refresh(alert)
                return _row_to_dict(alert)

    def update_status(self, alert_id: int, status: str, analyst: str = "", fp_reason: str = "") -> Optional[dict]:
        """Transition an alert to a new status and optionally record the analyst.

        Args:
            alert_id: Primary key of the alert to update.
            status: New status value (e.g. ``"Triage"``, ``"Closed"``,
                ``"Closed - FP"``).
            analyst: Username of the analyst performing the transition.
            fp_reason: Reason when the alert is being closed as a false
                positive; ignored for non-FP statuses.

        Returns:
            The updated alert dict, or ``None`` if no alert matches
            ``alert_id``.
        """
        now = self._now()
        with self._lock:
            with self._session() as session:
                alert = session.get(AlertRow, alert_id)
                if alert is None:
                    return None
                alert.status = status
                alert.updated_at = now
                if analyst:
                    alert.analyst = analyst
                if fp_reason:
                    alert.fp_reason = fp_reason
                session.commit()
                session.refresh(alert)
                return _row_to_dict(alert)

    def update_enrichment(self, alert_id: int, enrichment: dict) -> Optional[dict]:
        """Replace the enrichment payload on an existing alert.

        This is a full overwrite rather than a merge — callers are expected
        to read, modify, then write back the complete dict.

        Args:
            alert_id: Primary key of the alert.
            enrichment: New enrichment dict (will be JSON-serialised).

        Returns:
            The updated alert dict, or ``None`` if the alert was not found.
        """
        now = self._now()
        with self._lock:
            with self._session() as session:
                alert = session.get(AlertRow, alert_id)
                if alert is None:
                    return None
                alert.enrichment = json.dumps(enrichment)
                alert.updated_at = now
                session.commit()
                session.refresh(alert)
                return _row_to_dict(alert)

    def delete_alert(self, alert_id: int) -> bool:
        """Hard-delete an alert by primary key.

        Unlike ``delete_old_alerts`` which uses a bulk ``DELETE`` statement,
        this loads the row first so SQLAlchemy's identity map and any cascade
        rules are respected.

        Returns:
            ``True`` if the alert existed and was removed, ``False`` otherwise.
        """
        with self._lock:
            with self._session() as session:
                alert = session.get(AlertRow, alert_id)
                if alert is None:
                    return False
                session.delete(alert)
                session.commit()
                return True

    def get_alert(self, alert_id: int) -> Optional[dict]:
        """Fetch a single alert by primary key.

        Returns:
            Alert dict or ``None`` if not found.
        """
        with self._lock:
            with self._session() as session:
                alert = session.get(AlertRow, alert_id)
                return _row_to_dict(alert) if alert else None

    def list_alerts(self, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
        """List alerts with optional status filter, pagination, and total count.

        Results are ordered by ascending ``id`` (creation order).

        Args:
            status: If provided, only return alerts matching this status.
            limit: Maximum number of alerts to return (page size).
            offset: Number of alerts to skip (for pagination).

        Returns:
            A ``(alerts, total)`` tuple where *alerts* is the page of alert
            dicts and *total* is the count of all matching rows (before
            pagination).
        """
        with self._lock:
            with self._session() as session:
                from sqlalchemy import select, func

                stmt = select(AlertRow)
                count_stmt = select(func.count(AlertRow.id))

                if status:
                    stmt = stmt.where(AlertRow.status == status)
                    count_stmt = count_stmt.where(AlertRow.status == status)

                # Compute total count before applying LIMIT/OFFSET.
                total = session.scalar(count_stmt)
                stmt = stmt.order_by(AlertRow.id).limit(limit).offset(offset)
                rows = session.scalars(stmt).all()
                return [_row_to_dict(r) for r in rows], total

    def add_note(self, alert_id: int, note: str, analyst: str = "") -> Optional[dict]:
        """Append a timestamped analyst note to an alert.

        Notes are stored as a JSON array in the ``notes`` column.  Each call
        reads the current array, appends a new entry, and writes it back —
        the RLock prevents lost updates from concurrent calls.

        Args:
            alert_id: Primary key of the alert.
            note: Free-text note body.
            analyst: Username of the note author (defaults to ``"unknown"``).

        Returns:
            The updated alert dict, or ``None`` if not found.
        """
        now = self._now()
        with self._lock:
            with self._session() as session:
                alert = session.get(AlertRow, alert_id)
                if alert is None:
                    return None
                notes = json.loads(alert.notes) if alert.notes else []
                notes.append({"timestamp": now, "analyst": analyst or "unknown", "note": note})
                alert.notes = json.dumps(notes)
                alert.updated_at = now
                session.commit()
                session.refresh(alert)
                return _row_to_dict(alert)

    def count_alerts(self) -> int:
        """Return the total number of alerts in the database."""
        with self._lock:
            with self._session() as session:
                from sqlalchemy import func, select
                return session.scalar(select(func.count(AlertRow.id)))

    def delete_old_alerts(self, days: int = 90) -> int:
        """Bulk-delete closed alerts older than ``days`` days.

        Only alerts whose ``status`` is ``"Closed"`` or ``"Closed - FP"``
        are removed.  Open or triaged alerts are never pruned regardless of
        age — this prevents data loss on active investigations.

        Uses a bulk ``DELETE`` statement rather than loading rows individually
        for efficiency when the table is large.

        Args:
            days: Retention period in days.  Alerts created more than this
                many days ago (and already closed) are deleted.

        Returns:
            Number of rows deleted.
        """
        cutoff = self._cutoff(days=days)
        with self._lock:
            with self._session() as session:
                from sqlalchemy import delete
                stmt = (
                    delete(AlertRow)
                    .where(AlertRow.created_at < cutoff)
                    .where(AlertRow.status.in_(["Closed", "Closed - FP"]))
                )
                result = session.execute(stmt)
                session.commit()
                return result.rowcount

    def find_duplicate(self, title: str, source: str, ioc: str = "", within_seconds: int = 300) -> Optional[dict]:
        """Check for an existing alert with matching attributes within a time window.

        Duplicate detection is critical for alert-fatigue reduction — the
        same IOC firing repeatedly from the same source within a short period
        should be collapsed into a single alert.

        Args:
            title: Alert title to match.
            source: Source system to match.
            ioc: IOC string to match (empty string matches empty IOC).
            within_seconds: Time window in seconds; alerts older than this
                are ignored.

        Returns:
            The most recent matching alert dict, or ``None`` if no duplicate
            exists.
        """
        cutoff = self._cutoff(seconds=within_seconds)
        with self._lock:
            with self._session() as session:
                from sqlalchemy import select
                stmt = (
                    select(AlertRow)
                    .where(AlertRow.title == title)
                    .where(AlertRow.source == source)
                    .where(AlertRow.ioc == ioc)
                    .where(AlertRow.created_at > cutoff)
                    .order_by(AlertRow.id.desc())
                    .limit(1)
                )
                alert = session.scalars(stmt).first()
                return _row_to_dict(alert) if alert else None

    def migrate_from_json(self, json_path: str) -> int:
        """Import alerts from a legacy JSON file into the database.

        Expects the JSON to have an ``"alerts"`` key containing a list of
        alert objects with the same field names as ``AlertRow``.  Uses
        ``session.merge()`` so existing rows (matched by ``id``) are updated
        rather than causing constraint violations.

        This method is intended for one-time data migration from the original
        flat-file storage and should not be called in normal operation.

        Args:
            json_path: Path to the JSON file to import.

        Returns:
            Number of alerts imported/merged.
        """
        path = Path(json_path)
        if not path.exists():
            return 0
        data = json.loads(path.read_text())
        alerts = data.get("alerts", [])
        if not alerts:
            return 0
        count = 0
        with self._lock:
            with self._session() as session:
                for alert in alerts:
                    row = AlertRow(
                        id=alert["id"],
                        title=alert["title"],
                        severity=alert["severity"],
                        source=alert["source"],
                        ioc=alert.get("ioc", ""),
                        status=alert.get("status", "Open"),
                        created_at=alert.get("created_at", self._now()),
                        updated_at=alert.get("updated_at", self._now()),
                        analyst=alert.get("analyst", ""),
                        fp_reason=alert.get("fp_reason", ""),
                        enrichment=json.dumps(alert.get("enrichment", {})),
                        notes=json.dumps(alert.get("notes", [])),
                    )
                    # merge() performs INSERT OR UPDATE based on primary key,
                    # making the import idempotent.
                    session.merge(row)
                    count += 1
                session.commit()
        return count

    def close(self):
        """Dispose of the connection pool and mark the store as shut down.

        After calling this, no further database operations should be
        attempted on this instance.
        """
        with self._lock:
            self._engine.dispose()
            self._initialized = False
