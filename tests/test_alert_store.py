"""Tests for AlertStore (SQLite-backed)."""

import json
import tempfile
from pathlib import Path

from db import AlertStore


class TestAlertStore:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = AlertStore(self.tmp.name)

    def teardown_method(self):
        self.store.close()
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_empty_store(self):
        alerts, total = self.store.list_alerts()
        assert alerts == []
        assert total == 0

    def test_add_alert(self):
        alert = self.store.add_alert("Test Alert", "P1", "splunk", "8.8.8.8")
        assert alert["title"] == "Test Alert"
        assert alert["severity"] == "P1"
        assert alert["source"] == "splunk"
        assert alert["ioc"] == "8.8.8.8"
        assert alert["status"] == "Open"
        assert alert["id"] == 1

    def test_add_multiple_alerts(self):
        self.store.add_alert("Alert 1", "P1", "splunk")
        a2 = self.store.add_alert("Alert 2", "P2", "manual")
        assert a2["id"] == 2
        alerts, total = self.store.list_alerts()
        assert len(alerts) == 2
        assert total == 2

    def test_get_alert_by_id(self):
        self.store.add_alert("Test", "P3", "manual")
        alert = self.store.get_alert(1)
        assert alert is not None
        assert alert["title"] == "Test"

    def test_get_nonexistent_alert(self):
        assert self.store.get_alert(999) is None

    def test_update_status(self):
        self.store.add_alert("Test", "P2", "splunk")
        updated = self.store.update_status(1, "In Progress", "analyst1")
        assert updated is not None
        assert updated["status"] == "In Progress"
        assert updated["analyst"] == "analyst1"

    def test_update_status_preserves_existing_fields(self):
        self.store.add_alert("Test", "P1", "splunk")
        self.store.update_status(1, "In Progress", analyst="analyst1")
        updated = self.store.update_status(1, "Escalated")
        assert updated["analyst"] == "analyst1"

    def test_update_status_with_fp_reason(self):
        self.store.add_alert("Test", "P3", "manual")
        updated = self.store.update_status(1, "Closed - FP", fp_reason="scanner")
        assert updated["fp_reason"] == "scanner"

    def test_update_status_both_analyst_and_fp(self):
        self.store.add_alert("Test", "P1", "splunk")
        updated = self.store.update_status(1, "Closed - FP", analyst="analyst1", fp_reason="confirmed fp")
        assert updated["status"] == "Closed - FP"
        assert updated["analyst"] == "analyst1"
        assert updated["fp_reason"] == "confirmed fp"

    def test_update_nonexistent(self):
        assert self.store.update_status(999, "Closed") is None

    def test_list_by_status(self):
        self.store.add_alert("Alert 1", "P1", "splunk")
        self.store.add_alert("Alert 2", "P2", "manual")
        self.store.update_status(1, "Escalated")
        open_alerts, open_total = self.store.list_alerts("Open")
        escalated, esc_total = self.store.list_alerts("Escalated")
        assert len(open_alerts) == 1
        assert open_total == 1
        assert len(escalated) == 1
        assert esc_total == 1

    def test_list_pagination(self):
        for i in range(5):
            self.store.add_alert(f"Alert {i}", "P3", "manual")
        page1, total = self.store.list_alerts(limit=2, offset=0)
        assert len(page1) == 2
        assert total == 5
        page2, _ = self.store.list_alerts(limit=2, offset=2)
        assert len(page2) == 2
        page3, _ = self.store.list_alerts(limit=2, offset=4)
        assert len(page3) == 1

    def test_persistence(self):
        self.store.add_alert("Persistent", "P1", "splunk")
        self.store.close()
        store2 = AlertStore(self.tmp.name)
        alerts, total = store2.list_alerts()
        assert len(alerts) == 1
        assert total == 1
        assert store2.get_alert(1)["title"] == "Persistent"
        store2.close()

    def test_add_alert_with_defaults(self):
        alert = self.store.add_alert("Minimal", "P3", "manual")
        assert alert["status"] == "Open"
        assert alert["analyst"] == ""
        assert alert["notes"] == []
        assert alert["fp_reason"] == ""

    def test_add_alert_without_ioc(self):
        alert = self.store.add_alert("No IOC", "P4", "manual")
        assert alert["ioc"] == ""

    def test_add_alert_with_enrichment(self):
        enrichment = {"ips": ["8.8.8.8"], "domains": ["evil.com"]}
        alert = self.store.add_alert("Enriched", "P1", "manual", ioc="8.8.8.8", enrichment=enrichment)
        assert alert["enrichment"] == enrichment

    def test_update_enrichment(self):
        self.store.add_alert("Test", "P3", "manual")
        enrichment = {"ips": ["10.0.0.1"], "type": "ip"}
        updated = self.store.update_enrichment(1, enrichment)
        assert updated is not None
        assert updated["enrichment"] == enrichment

    def test_update_enrichment_nonexistent(self):
        assert self.store.update_enrichment(999, {}) is None

    def test_delete_alert(self):
        self.store.add_alert("To Delete", "P3", "manual")
        assert self.store.delete_alert(1) is True
        assert self.store.get_alert(1) is None

    def test_delete_nonexistent(self):
        assert self.store.delete_alert(999) is False

    def test_add_note(self):
        self.store.add_alert("Alert with note", "P2", "splunk")
        updated = self.store.add_note(1, "Investigated further", "analyst1")
        assert updated is not None
        assert len(updated["notes"]) == 1
        assert updated["notes"][0]["note"] == "Investigated further"
        assert updated["notes"][0]["analyst"] == "analyst1"

    def test_add_note_nonexistent(self):
        assert self.store.add_note(999, "note") is None

    def test_multiple_notes(self):
        self.store.add_alert("Multi note", "P3", "manual")
        self.store.add_note(1, "First", "analyst1")
        self.store.add_note(1, "Second", "analyst2")
        alert = self.store.get_alert(1)
        assert len(alert["notes"]) == 2


class TestMigration:
    def setup_method(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_db.close()
        self.tmp_json = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False)
        self.store = AlertStore(self.tmp_db.name)

    def teardown_method(self):
        self.store.close()
        Path(self.tmp_db.name).unlink(missing_ok=True)
        Path(self.tmp_json.name).unlink(missing_ok=True)

    def test_migrate_empty_json(self):
        self.tmp_json.write(json.dumps({"alerts": []}))
        self.tmp_json.close()
        count = self.store.migrate_from_json(self.tmp_json.name)
        assert count == 0

    def test_migrate_from_json(self):
        data = {
            "alerts": [
                {"id": 1, "title": "Alert 1", "severity": "P1", "source": "splunk",
                 "ioc": "8.8.8.8", "status": "Open", "created_at": "2026-01-01T00:00:00",
                 "updated_at": "2026-01-01T00:00:00", "analyst": "", "fp_reason": "",
                 "enrichment": {}, "notes": []},
                {"id": 2, "title": "Alert 2", "severity": "P2", "source": "manual",
                 "ioc": "", "status": "Escalated", "created_at": "2026-01-02T00:00:00",
                 "updated_at": "2026-01-02T00:00:00", "analyst": "jsmith", "fp_reason": "",
                 "enrichment": {"vt": {}}, "notes": [{"timestamp": "2026-01-02T01:00:00", "analyst": "jsmith", "note": "checked"}]},
            ]
        }
        self.tmp_json.write(json.dumps(data))
        self.tmp_json.close()
        count = self.store.migrate_from_json(self.tmp_json.name)
        assert count == 2
        alerts, total = self.store.list_alerts()
        assert len(alerts) == 2
        assert total == 2
        a1 = self.store.get_alert(1)
        assert a1["title"] == "Alert 1"
        a2 = self.store.get_alert(2)
        assert a2["analyst"] == "jsmith"
        assert a2["enrichment"]["vt"] == {}
        assert len(a2["notes"]) == 1

    def test_migrate_nonexistent_file(self):
        count = self.store.migrate_from_json("/nonexistent/file.json")
        assert count == 0