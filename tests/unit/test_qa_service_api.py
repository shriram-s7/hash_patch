"""tests/unit/test_qa_service_api.py — Tests for /api/ask with normalized scan resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx
from hash_patch.qa.registry import GLOBAL_SCAN_REGISTRY
from hash_patch.service import app

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def clean_registry() -> None:
    GLOBAL_SCAN_REGISTRY.clear()


@pytest.fixture(scope="module")
def test2_cbom() -> dict:
    result = run_scan(REPO_ROOT / "test2")
    return to_cyclonedx(result)


def test_legacy_ask_with_cbom_registers_and_succeeds(test2_cbom: dict) -> None:
    client = TestClient(app)

    # Legacy request: only cbom and question
    resp = client.post(
        "/api/ask",
        json={
            "cbom": test2_cbom,
            "question": "what is this scan?",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["grounded"] is True
    assert "scan_id" in data
    assert data["scan_id"] == test2_cbom.get("serialNumber")

    # Verify it was auto-registered in GLOBAL_SCAN_REGISTRY
    assert GLOBAL_SCAN_REGISTRY.get_scan(data["scan_id"]) is not None


def test_scan_directory_registers_cbom_for_subsequent_ask_by_scan_id() -> None:
    client = TestClient(app)

    # Step 1: Run scan via /api/scan
    scan_resp = client.post("/api/scan", json={"path": str(REPO_ROOT / "test2")})
    assert scan_resp.status_code == 200
    cbom = scan_resp.json()
    serial = cbom["serialNumber"]
    assert serial is not None

    # Step 2: Query /api/ask using ONLY scan_id (no cbom payload!)
    ask_resp = client.post(
        "/api/ask",
        json={
            "scan_id": serial,
            "question": "how many findings were found?",
        },
    )
    assert ask_resp.status_code == 200
    data = ask_resp.json()
    assert data["grounded"] is True
    assert data["scan_id"] == serial


def test_unknown_scan_id_without_cbom_returns_404() -> None:
    client = TestClient(app)

    resp = client.post(
        "/api/ask",
        json={
            "scan_id": "urn:uuid:nonexistent-scan-id-9999",
            "question": "tell me about RSA",
        },
    )
    assert resp.status_code == 404
    assert "not found in registry" in resp.json()["detail"]


def test_unknown_scan_id_with_fallback_cbom_auto_registers_and_succeeds(test2_cbom: dict) -> None:
    client = TestClient(app)

    # Client specifies a scan_id not yet known, but includes cbom fallback
    resp = client.post(
        "/api/ask",
        json={
            "scan_id": "urn:uuid:custom-session-scan",
            "cbom": test2_cbom,
            "question": "what is the highest risk finding?",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["grounded"] is True
    assert data["scan_id"] == "urn:uuid:custom-session-scan"


def test_missing_both_scan_id_and_cbom_returns_400() -> None:
    client = TestClient(app)

    resp = client.post(
        "/api/ask",
        json={
            "question": "what did you find?",
        },
    )
    assert resp.status_code == 400
    assert "Either 'scan_id' or 'cbom'" in resp.json()["detail"]


def test_conversation_id_and_session_id_alias_support(test2_cbom: dict) -> None:
    client = TestClient(app)
    serial = test2_cbom["serialNumber"]

    # Pre-register scan
    GLOBAL_SCAN_REGISTRY.register_scan(test2_cbom)

    # Turn 1 with session_id (legacy alias)
    r1 = client.post(
        "/api/ask",
        json={
            "scan_id": serial,
            "question": "tell me about RSA",
            "session_id": "sess_123",
        },
    )
    assert r1.status_code == 200

    # Turn 2 with conversation_id (new canonical field)
    r2 = client.post(
        "/api/ask",
        json={
            "scan_id": serial,
            "question": "is it live?",
            "conversation_id": "sess_123",
        },
    )
    assert r2.status_code == 200
    data2 = r2.json()
    # Verified pronoun resolution worked via the shared session key
    assert "RSA" in data2["matched_findings"]
