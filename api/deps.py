"""API dependencies."""

import os

from db import AlertStore

_store: AlertStore | None = None


def get_store() -> AlertStore:
    global _store
    if _store is None:
        db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
        _store = AlertStore(db_path)
    return _store