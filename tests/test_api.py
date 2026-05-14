"""Tests for AlertFlow REST API."""

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.deps import get_store
from db import AlertStore


def _make_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = AlertStore(tmp.name)
    return store, tmp.name


class TestHealthEndpoint:
    def test_health(self):
        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == "0.6.0"


class TestAlertCRUD:
    @pytest.fixture(autouse=True)
    def setup_store(self):
        store, db_path = _make_store()
        app.dependency_overrides[get_store] = lambda: store
        self.client = TestClient(app)
        self.db_path = db_path
        yield
        store.close()
        Path(db_path).unlink(missing_ok=True)
        app.dependency_overrides.clear()

    def test_create_alert(self):
        resp = self.client.post("/api/alerts", json={
            "title": "Test Alert",
            "severity": "P1",
            "source": "test",
            "ioc": "10.0.0.1",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Test Alert"
        assert data["severity"] == "P1"
        assert data["status"] == "Open"
        assert data["id"] == 1

    def test_list_alerts_empty(self):
        resp = self.client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["alerts"] == []
        assert data["limit"] == 100
        assert data["offset"] == 0

    def test_list_alerts_with_data(self):
        self.client.post("/api/alerts", json={"title": "A1", "severity": "P2", "source": "test"})
        self.client.post("/api/alerts", json={"title": "A2", "severity": "P1", "source": "test"})
        resp = self.client.get("/api/alerts")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_list_alerts_pagination(self):
        for i in range(5):
            self.client.post("/api/alerts", json={"title": f"Alert {i}", "severity": "P3", "source": "test"})
        resp = self.client.get("/api/alerts?limit=2&offset=0")
        data = resp.json()
        assert len(data["alerts"]) == 2
        assert data["total"] == 5
        resp2 = self.client.get("/api/alerts?limit=2&offset=2")
        assert len(resp2.json()["alerts"]) == 2
        resp3 = self.client.get("/api/alerts?limit=2&offset=4")
        assert len(resp3.json()["alerts"]) == 1

    def test_get_alert_by_id(self):
        create_resp = self.client.post("/api/alerts", json={"title": "Fetch Me", "severity": "P3", "source": "test"})
        alert_id = create_resp.json()["id"]
        resp = self.client.get(f"/api/alerts/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "Fetch Me"

    def test_get_nonexistent_alert(self):
        resp = self.client.get("/api/alerts/999")
        assert resp.status_code == 404

    def test_update_alert_status(self):
        create_resp = self.client.post("/api/alerts", json={"title": "Update Me", "severity": "P2", "source": "test"})
        alert_id = create_resp.json()["id"]
        resp = self.client.patch(f"/api/alerts/{alert_id}", json={
            "status": "In Progress",
            "analyst": "jsmith",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "In Progress"
        assert resp.json()["analyst"] == "jsmith"

    def test_update_enrichment(self):
        create_resp = self.client.post("/api/alerts", json={"title": "Enrich Me", "severity": "P2", "source": "test"})
        alert_id = create_resp.json()["id"]
        enrichment = {"ip_8.8.8.8": {"type": "ip", "checks": {"dns": "dns.google"}}}
        resp = self.client.patch(f"/api/alerts/{alert_id}/enrichment", json={"enrichment": enrichment})
        assert resp.status_code == 200
        assert resp.json()["enrichment"]["ip_8.8.8.8"]["type"] == "ip"

    def test_close_alert_as_fp(self):
        create_resp = self.client.post("/api/alerts", json={"title": "FP Alert", "severity": "P3", "source": "test"})
        alert_id = create_resp.json()["id"]
        resp = self.client.patch(f"/api/alerts/{alert_id}", json={
            "status": "Closed - FP",
            "analyst": "jsmith",
            "fp_reason": "vulnerability scanner",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "Closed - FP"
        assert resp.json()["fp_reason"] == "vulnerability scanner"

    def test_filter_by_status(self):
        self.client.post("/api/alerts", json={"title": "Open 1", "severity": "P3", "source": "test"})
        r2 = self.client.post("/api/alerts", json={"title": "Escalated 1", "severity": "P1", "source": "test"})
        alert_id = r2.json()["id"]
        self.client.patch(f"/api/alerts/{alert_id}", json={"status": "Escalated"})
        open_alerts = self.client.get("/api/alerts?status=Open").json()
        escalated = self.client.get("/api/alerts?status=Escalated").json()
        assert open_alerts["total"] == 1
        assert escalated["total"] == 1

    def test_add_note(self):
        create_resp = self.client.post("/api/alerts", json={"title": "Noted Alert", "severity": "P2", "source": "test"})
        alert_id = create_resp.json()["id"]
        resp = self.client.post(f"/api/alerts/{alert_id}/notes", json={
            "note": "Investigated — confirmed false positive",
            "analyst": "jsmith",
        })
        assert resp.status_code == 200
        assert len(resp.json()["notes"]) == 1
        assert resp.json()["notes"][0]["note"] == "Investigated — confirmed false positive"

    def test_delete_alert(self):
        create_resp = self.client.post("/api/alerts", json={"title": "Delete Me", "severity": "P3", "source": "test"})
        alert_id = create_resp.json()["id"]
        resp = self.client.delete(f"/api/alerts/{alert_id}")
        assert resp.status_code == 204
        get_resp = self.client.get(f"/api/alerts/{alert_id}")
        assert get_resp.status_code == 404

    def test_delete_nonexistent(self):
        resp = self.client.delete("/api/alerts/999")
        assert resp.status_code == 404

    def test_create_alert_with_severity_validation(self):
        resp = self.client.post("/api/alerts", json={"title": "Bad", "severity": "P99", "source": "test"})
        assert resp.status_code == 422


class TestEnrichEndpoint:
    def test_enrich_ip(self):
        client = TestClient(app)
        resp = client.post("/api/enrich", json={"target": "8.8.8.8"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target"] == "8.8.8.8"
        assert data["target_type"] == "ip"
        assert "checks" in data

    def test_enrich_hash(self):
        client = TestClient(app)
        resp = client.post("/api/enrich", json={"target": "d41d8cd98f00b204e9800998ecf8427e"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_type"] == "hash"

    def test_enrich_domain(self):
        client = TestClient(app)
        resp = client.post("/api/enrich", json={"target": "google.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_type"] == "domain"

    def test_enrich_explicit_type(self):
        client = TestClient(app)
        resp = client.post("/api/enrich", json={"target": "admin", "target_type": "user"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_type"] == "user"