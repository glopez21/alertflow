"""Alert storage — supports SQLite (dev/test) and MySQL (production)."""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


def _alert_from_row(row) -> dict:
    if isinstance(row, sqlite3.Row):
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
    else:
        return {
            "id": row[0],
            "title": row[1],
            "severity": row[2],
            "source": row[3],
            "ioc": row[4] or "",
            "status": row[5],
            "created_at": row[6],
            "updated_at": row[7],
            "analyst": row[8] or "",
            "fp_reason": row[9] or "",
            "enrichment": json.loads(row[10]) if row[10] else {},
            "notes": json.loads(row[11]) if row[11] else [],
        }


def _parse_mysql_row(cursor) -> Optional[dict]:
    """Parse a single MySQL row with JSON fields."""
    row = cursor.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in cursor.description]
    d = {col: row[i] for i, col in enumerate(cols)}
    d["enrichment"] = json.loads(d.get("enrichment") or "{}")
    d["notes"] = json.loads(d.get("notes") or "[]")
    return d


def _parse_mysql_rows(cursor) -> list[dict]:
    """Parse multiple MySQL rows with JSON fields."""
    cols = [d[0] for d in cursor.description]
    rows = cursor.fetchall()
    result = []
    for row in rows:
        d = {col: row[i] for i, col in enumerate(cols)}
        d["enrichment"] = json.loads(d.get("enrichment") or "{}")
        d["notes"] = json.loads(d.get("notes") or "[]")
        result.append(d)
    return result


class AlertStore:
    """Alert storage backed by SQLite or MySQL."""

    def __init__(self, db_path: str | None = None, *, mysql_url: str | None = None):
        self._backend = "mysql" if mysql_url else "sqlite"
        self._lock = threading.RLock()

        if self._backend == "mysql":
            import urllib.parse
            parsed = urllib.parse.urlparse(mysql_url)
            self._mysql_config = {
                "host": parsed.hostname or "localhost",
                "port": parsed.port or 3306,
                "user": parsed.username or "root",
                "password": parsed.password or "",
                "database": (parsed.path or "/alertflow").lstrip("/"),
                "charset": "utf8mb4",
                "autocommit": False,
            }
            self._conn = None
            self._initialized = False
        else:
            if db_path is None:
                db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
            self.db_path = Path(db_path)
            self._conn: sqlite3.Connection | None = None
            self._initialized = False

    def _get_conn(self):
        if self._initialized and self._conn is not None:
            return self._conn
        with self._lock:
            if self._conn is not None:
                return self._conn
            if self._backend == "mysql":
                self._conn = self._connect_mysql()
                self._init_db_mysql()
            else:
                self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._init_db_sqlite()
            self._initialized = True
            return self._conn

    def _connect_mysql(self):
        try:
            import aiomysql
        except ImportError:
            raise ImportError("aiomysql is required for MySQL backend: pip install aiomysql")
        import asyncio

        cfg = self._mysql_config.copy()

        async def _connect():
            return await aiomysql.connect(
                host=cfg["host"],
                port=cfg["port"],
                user=cfg["user"],
                password=cfg["password"],
                db=cfg["database"],
                charset=cfg["charset"],
                autocommit=False,
            )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                conn = pool.submit(asyncio.run, _connect()).result()
        else:
            conn = asyncio.run(_connect())
        return conn

    def _init_db_sqlite(self):
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

    def _init_db_mysql(self):
        cur = self._conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(500) NOT NULL,
                severity VARCHAR(10) NOT NULL,
                source VARCHAR(100) NOT NULL,
                ioc VARCHAR(500) DEFAULT '',
                status VARCHAR(50) DEFAULT 'Open',
                created_at VARCHAR(50) NOT NULL,
                updated_at VARCHAR(50) NOT NULL,
                analyst VARCHAR(100) DEFAULT '',
                fp_reason VARCHAR(1000) DEFAULT '',
                enrichment LONGTEXT DEFAULT '{}',
                notes LONGTEXT DEFAULT '[]'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        self._conn.commit()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _cutoff(self, seconds: int = 0, days: int = 0) -> str:
        """Return a cutoff timestamp in the same format as _now()."""
        dt = datetime.now(timezone.utc) - timedelta(seconds=seconds, days=days)
        return dt.isoformat().replace("+00:00", "Z")

    def add_alert(self, title: str, severity: str, source: str, ioc: str = "", enrichment: dict | None = None) -> dict:
        now = self._now()
        enrichment_json = json.dumps(enrichment) if enrichment else "{}"
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute(
                    """INSERT INTO alerts (title, severity, source, ioc, status, created_at, updated_at, enrichment)
                       VALUES (%s, %s, %s, %s, 'Open', %s, %s, %s)""",
                    (title, severity, source, ioc, now, now, enrichment_json),
                )
                conn.commit()
                cur.execute("SELECT * FROM alerts WHERE id = %s", (cur.lastrowid,))
                return _parse_mysql_row(cur)
            else:
                cur = conn.execute(
                    """INSERT INTO alerts (title, severity, source, ioc, status, created_at, updated_at, enrichment)
                       VALUES (?, ?, ?, ?, 'Open', ?, ?, ?)""",
                    (title, severity, source, ioc, now, now, enrichment_json),
                )
                conn.commit()
                row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
                return _alert_from_row(row)

    def update_status(self, alert_id: int, status: str, analyst: str = "", fp_reason: str = "") -> Optional[dict]:
        now = self._now()
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("SELECT analyst, fp_reason FROM alerts WHERE id = %s", (alert_id,))
                row = cur.fetchone()
                if row is None:
                    return None
                current_analyst = row[0] or ""
                current_fp = row[1] or ""
                final_analyst = analyst if analyst else current_analyst
                final_fp = fp_reason if fp_reason else current_fp
                cur.execute(
                    "UPDATE alerts SET status=%s, updated_at=%s, analyst=%s, fp_reason=%s WHERE id=%s",
                    (status, now, final_analyst, final_fp, alert_id),
                )
                conn.commit()
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                return _parse_mysql_row(cur)
            else:
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
                return _alert_from_row(updated)

    def update_enrichment(self, alert_id: int, enrichment: dict) -> Optional[dict]:
        now = self._now()
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("SELECT id FROM alerts WHERE id = %s", (alert_id,))
                if cur.fetchone() is None:
                    return None
                cur.execute(
                    "UPDATE alerts SET enrichment=%s, updated_at=%s WHERE id=%s",
                    (json.dumps(enrichment), now, alert_id),
                )
                conn.commit()
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                return _parse_mysql_row(cur)
            else:
                row = conn.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                if row is None:
                    return None
                conn.execute(
                    "UPDATE alerts SET enrichment=?, updated_at=? WHERE id=?",
                    (json.dumps(enrichment), now, alert_id),
                )
                conn.commit()
                updated = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                return _alert_from_row(updated)

    def delete_alert(self, alert_id: int) -> bool:
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("DELETE FROM alerts WHERE id = %s", (alert_id,))
                conn.commit()
                return cur.rowcount > 0
            else:
                cur = conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
                conn.commit()
                return cur.rowcount > 0

    def get_alert(self, alert_id: int) -> Optional[dict]:
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                return _parse_mysql_row(cur)
            else:
                row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                return _alert_from_row(row) if row else None

    def list_alerts(self, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> tuple[list[dict], int]:
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                if status:
                    cur.execute("SELECT COUNT(*) FROM alerts WHERE status = %s", (status,))
                    total = cur.fetchone()[0]
                    cur.execute(
                        "SELECT * FROM alerts WHERE status = %s ORDER BY id LIMIT %s OFFSET %s",
                        (status, limit, offset),
                    )
                else:
                    cur.execute("SELECT COUNT(*) FROM alerts")
                    total = cur.fetchone()[0]
                    cur.execute("SELECT * FROM alerts ORDER BY id LIMIT %s OFFSET %s", (limit, offset))
                return _parse_mysql_rows(cur), total
            else:
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
                return [_alert_from_row(r) for r in rows], total

    def add_note(self, alert_id: int, note: str, analyst: str = "") -> Optional[dict]:
        now = self._now()
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("SELECT notes FROM alerts WHERE id = %s", (alert_id,))
                row = cur.fetchone()
                if row is None:
                    return None
                notes = json.loads(row[0]) if row[0] else []
                notes.append({"timestamp": now, "analyst": analyst or "unknown", "note": note})
                cur.execute(
                    "UPDATE alerts SET notes=%s, updated_at=%s WHERE id=%s",
                    (json.dumps(notes), now, alert_id),
                )
                conn.commit()
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                return _parse_mysql_row(cur)
            else:
                row = conn.execute("SELECT notes FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                if row is None:
                    return None
                notes = json.loads(row["notes"]) if row["notes"] else []
                notes.append({"timestamp": now, "analyst": analyst or "unknown", "note": note})
                conn.execute(
                    "UPDATE alerts SET notes=?, updated_at=? WHERE id=?",
                    (json.dumps(notes), now, alert_id),
                )
                conn.commit()
                updated = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                return _alert_from_row(updated)

    def count_alerts(self) -> int:
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM alerts")
                return cur.fetchone()[0]
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def delete_old_alerts(self, days: int = 90) -> int:
        """Delete alerts older than N days. Returns count deleted."""
        cutoff = self._cutoff(days=days)
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute("DELETE FROM alerts WHERE created_at < %s AND status IN ('Closed', 'Closed - FP')", (cutoff,))
                conn.commit()
                return cur.rowcount
            else:
                cur = conn.execute(
                    "DELETE FROM alerts WHERE created_at < ? AND status IN ('Closed', 'Closed - FP')",
                    (cutoff,),
                )
                conn.commit()
                return cur.rowcount

    def find_duplicate(self, title: str, source: str, ioc: str = "", within_seconds: int = 300) -> Optional[dict]:
        """Check for a recent duplicate alert (same title+source+IOC within N seconds)."""
        cutoff = self._cutoff(seconds=within_seconds)
        with self._lock:
            conn = self._get_conn()
            if self._backend == "mysql":
                cur = conn.cursor()
                cur.execute(
                    "SELECT * FROM alerts WHERE title=%s AND source=%s AND ioc=%s AND created_at > %s ORDER BY id DESC LIMIT 1",
                    (title, source, ioc, cutoff),
                )
                return _parse_mysql_row(cur)
            else:
                row = conn.execute(
                    "SELECT * FROM alerts WHERE title=? AND source=? AND ioc=? AND created_at > ? ORDER BY id DESC LIMIT 1",
                    (title, source, ioc, cutoff),
                ).fetchone()
                return _alert_from_row(row) if row else None

    def migrate_from_json(self, json_path: str) -> int:
        """Import alerts from a JSON file. Returns count migrated."""
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
                if self._backend == "mysql":
                    cur = conn.cursor()
                    cur.execute(
                        """INSERT INTO alerts
                           (id, title, severity, source, ioc, status, created_at, updated_at,
                            analyst, fp_reason, enrichment, notes)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (
                            alert["id"], alert["title"], alert["severity"], alert["source"],
                            alert.get("ioc", ""), alert.get("status", "Open"),
                            alert.get("created_at", self._now()),
                            alert.get("updated_at", self._now()),
                            alert.get("analyst", ""), alert.get("fp_reason", ""),
                            enrichment, notes,
                        ),
                    )
                else:
                    conn.execute(
                        """INSERT INTO alerts
                           (id, title, severity, source, ioc, status, created_at, updated_at,
                            analyst, fp_reason, enrichment, notes)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            alert["id"], alert["title"], alert["severity"], alert["source"],
                            alert.get("ioc", ""), alert.get("status", "Open"),
                            alert.get("created_at", self._now()),
                            alert.get("updated_at", self._now()),
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
