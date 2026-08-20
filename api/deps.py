"""API dependencies."""

import os
import threading

from db import AlertStore

_store: AlertStore | None = None
_store_lock = threading.Lock()


def get_store() -> AlertStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is not None:
            return _store
        mysql_url = os.environ.get("ALERTFLOW_MYSQL_URL", "")
        if mysql_url:
            _store = AlertStore(mysql_url=mysql_url)
        else:
            db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
            _store = AlertStore(db_path)
    return _store
