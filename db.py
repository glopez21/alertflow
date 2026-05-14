"""SQLite-backed alert storage for AlertFlow."""

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional


def _alert_from_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "severity": row["severity"],
        "source": row["source"],
        "ioc": row["ioc"] or "",
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "analyst": row["analyst"] or "",
        "fp_reason": row["fp_reason"] or "",
        "enrichment": json.loads(row["enrichment"]) if row["enrichment"] else {},
        "notes": json.loads(row["notes"]) if row["notes"] else [],
    }


class AlertStore:
    """SQLite-backed alert storage."""

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._initialized = False

    def _get_conn(self) -> sqlite3.Connection:
        if self._initialized and self._conn is not None:
            return self._conn
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._init_db()
                self._initialized = True
            return self._conn

    def _init_db(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                ioc TEXT DEFAULT '',
                status TEXT DEFAULT 'Open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                analyst TEXT DEFAULT '',
                fp_reason TEXT DEFAULT '',
                enrichment TEXT DEFAULT '{}',
                notes TEXT DEFAULT '[]'
            )
        """)
        self._conn.commit()

    def _row_to_dict(self, row: sqlite3.Row | None) -> Optional[dict]:
        if row is None:
            return None
        return _alert_from_row(row)

    def add_alert(self, title: str, severity: str, source: str, ioc: str = "", enrichment: dict | None = None) -> dict:
        now = datetime.now().isoformat()
        enrichment_json = json.dumps(enrichment) if enrichment else "{}"
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute(
                """INSERT INTO alerts (title, severity, source, ioc, status, created_at, updated_at, enrichment)
                   VALUES (?, ?, ?, ?, 'Open', ?, ?, ?)""",
                (title, severity, source, ioc, now, now, enrichment_json),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._row_to_dict(row)

    def update_status(self, alert_id: int, status: str, analyst: str = "", fp_reason: str = "") -> Optional[dict]:
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT analyst, fp_reason FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            current_analyst = row["analyst"] or ""
            current_fp = row["fp_reason"] or ""
            final_analyst = analyst if analyst else current_analyst
            final_fp = fp_reason if fp_reason else current_fp
            conn.execute(
                "UPDATE alerts SET status=?, updated_at=?, analyst=?, fp_reason=? WHERE id=?",
                (status, now, final_analyst, final_fp, alert_id),
            )
            conn.commit()
            updated = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(updated)

    def update_enrichment(self, alert_id: int, enrichment: dict) -> Optional[dict]:
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE alerts SET enrichment=?, updated_at=? WHERE id=?",
                (json.dumps(enrichment), now, alert_id),
            )
            conn.commit()
            updated = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(updated)

    def delete_alert(self, alert_id: int) -> bool:
        with self._lock:
            conn = self._get_conn()
            cur = conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            conn.commit()
            return cur.rowcount > 0

    def get_alert(self, alert_id: int) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return self._row_to_dict(row)

    def list_alerts(self, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
        conn = self._get_conn()
        if status:
            total = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = ?", (status,)).fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM alerts WHERE status = ? ORDER BY id LIMIT ? OFFSET ?",
                (status, limit, offset),
            ).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows], total

    def add_note(self, alert_id: int, note: str, analyst: str = "") -> Optional[dict]:
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT notes FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                return None
            notes = json.loads(row["notes"]) if row["notes"] else []
            notes.append({
                "timestamp": now,
                "analyst": analyst or "unknown",
                "note": note,
            })
            conn.execute(
                "UPDATE alerts SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(notes), now, alert_id),
            )
            conn.commit()
            updated = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(updated)

    def migrate_from_json(self, json_path: str) -> int:
        """Import alerts from a JSON file into SQLite. Returns count migrated."""
        path = Path(json_path)
        if not path.exists():
            return 0
        data = json.loads(path.read_text())
        alerts = data.get("alerts", [])
        if not alerts:
            return 0
        count = 0
        with self._lock:
            conn = self._get_conn()
            for alert in alerts:
                notes = json.dumps(alert.get("notes", []))
                enrichment = json.dumps(alert.get("enrichment", {}))
                conn.execute(
                    """INSERT INTO alerts
                       (id, title, severity, source, ioc, status, created_at, updated_at,
                        analyst, fp_reason, enrichment, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert["id"], alert["title"], alert["severity"], alert["source"],
                        alert.get("ioc", ""), alert.get("status", "Open"),
                        alert.get("created_at", datetime.now().isoformat()),
                        alert.get("updated_at", datetime.now().isoformat()),
                        alert.get("analyst", ""), alert.get("fp_reason", ""),
                        enrichment, notes,
                    ),
                )
                count += 1
            conn.commit()
        return count

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
                self._initialized = False