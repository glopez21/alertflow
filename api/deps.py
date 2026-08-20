"""API dependency injection — thread-safe singleton store.

Provides ``get_store()``, the sole factory/accessor for the backing
``AlertStore`` instance used by every route and the health probe.

Design:
- Uses a double-checked locking pattern (``threading.Lock``) to ensure the
  store is initialized exactly once, even under concurrent first-request races.
- Selects between MySQL and SQLite backends based on environment variables,
  making local development zero-config while supporting production MySQL.

Backend selection priority:
  1. ``ALERTFLOW_MYSQL_URL`` — if set and non-empty, connect to MySQL.
  2. ``ALERTFLOW_DB`` — SQLite file path (default ``alertflow.db``).
"""

import os
import threading

from db import AlertStore

# Module-level singleton; protected by _store_lock for thread-safe lazy init.
_store: AlertStore | None = None
_store_lock = threading.Lock()


def get_store() -> AlertStore:
    """Return the singleton AlertStore, creating it on first call.

    The fast-path check (without lock) avoids lock contention on every request
    once the store is initialized.  The lock is only acquired on the very first
    call or during shutdown/re-init scenarios.

    Returns:
        The shared AlertStore instance configured from environment variables.
    """
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        # Double-check after acquiring lock — another thread may have init'd.
        if _store is not None:
            return _store
        mysql_url = os.environ.get("ALERTFLOW_MYSQL_URL", "")
        if mysql_url:
            _store = AlertStore(mysql_url=mysql_url)
        else:
            # Default to local SQLite for zero-config development.
            db_path = os.environ.get("ALERTFLOW_DB", "alertflow.db")
            _store = AlertStore(db_path)
    return _store
