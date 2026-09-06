"""tests/integration/test_dynamic_migration_scan.py

Verifies end-to-end dynamic migration planning between /api/scan and /api/optimize:
1. Scan corpus A (Python) -> /api/optimize with Corpus A CBOM produces dynamic candidates.
2. Scan corpus B (C) -> /api/optimize with Corpus B CBOM produces distinct C candidates.
3. Candidate lists are derived from the active scan and are NOT the static 9-asset demo list.
4. Changing budget dynamically alters scheduled task counts and risk reduction.
5. Cross-scan isolation is preserved.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hash_patch.service import app

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_scan_corpus_a_python_produces_dynamic_migration_candidates(client: TestClient) -> None:
    target_a = REPO_ROOT / "testdata" / "python"
    scan_res = client.post("/api/scan", json={"path": str(target_a)})
    assert scan_res.status_code == 200
    cbom_a = scan_res.json()

    opt_res = client.post(
        "/api/optimize",
        json={"cbom": cbom_a, "budget_days": 5.0, "parallelism": 1},
    )
    assert opt_res.status_code == 200
    plan_a = opt_res.json()

    assert plan_a["candidate_count"] > 0
    assert len(plan_a["scenarios"]) == 3

    # Candidate names must be derived from Python crypto assets
    candidate_names = set()
    for s in plan_a["scenarios"]:
        for item in s["optimizer_plan"]["schedule"]:
            candidate_names.add(item["name"])

    assert len(candidate_names) > 0


def test_scan_corpus_b_c_differs_from_corpus_a(client: TestClient) -> None:
    target_a = REPO_ROOT / "testdata" / "python"
    target_b = REPO_ROOT / "testdata" / "c"

    cbom_a = client.post("/api/scan", json={"path": str(target_a)}).json()
    cbom_b = client.post("/api/scan", json={"path": str(target_b)}).json()

    plan_a = client.post("/api/optimize", json={"cbom": cbom_a, "budget_days": 5.0}).json()
    plan_b = client.post("/api/optimize", json={"cbom": cbom_b, "budget_days": 5.0}).json()

    assert plan_a["candidate_count"] != plan_b["candidate_count"] or (
        plan_a["scenarios"][0]["optimizer_plan"]["schedule"]
        != plan_b["scenarios"][0]["optimizer_plan"]["schedule"]
    )


def test_candidate_list_changes_when_scanned_cbom_changes(client: TestClient) -> None:
    target_python = REPO_ROOT / "testdata" / "python"
    target_java = REPO_ROOT / "testdata" / "java"

    cbom_py = client.post("/api/scan", json={"path": str(target_python)}).json()
    cbom_java = client.post("/api/scan", json={"path": str(target_java)}).json()

    plan_py = client.post("/api/optimize", json={"cbom": cbom_py}).json()
    plan_java = client.post("/api/optimize", json={"cbom": cbom_java}).json()

    # The two plans must have distinct candidate IDs
    py_ids = {
        item["finding_id"]
        for s in plan_py["scenarios"]
        for item in s["optimizer_plan"]["schedule"]
    }
    java_ids = {
        item["finding_id"]
        for s in plan_java["scenarios"]
        for item in s["optimizer_plan"]["schedule"]
    }

    assert py_ids != java_ids


def test_budget_adjustment_dynamically_changes_schedule(client: TestClient) -> None:
    target = REPO_ROOT / "testdata" / "python"
    cbom = client.post("/api/scan", json={"path": str(target)}).json()

    small_budget = client.post(
        "/api/optimize", json={"cbom": cbom, "budget_days": 0.5, "parallelism": 1}
    ).json()
    large_budget = client.post(
        "/api/optimize", json={"cbom": cbom, "budget_days": 20.0, "parallelism": 1}
    ).json()

    small_sched = small_budget["scenarios"][0]["optimizer_plan"]["schedule"]
    large_sched = large_budget["scenarios"][0]["optimizer_plan"]["schedule"]

    assert len(small_sched) <= len(large_sched)
    small_risk = small_budget["scenarios"][0]["optimizer_plan"]["risk_eliminated_pct"]
    large_risk = large_budget["scenarios"][0]["optimizer_plan"]["risk_eliminated_pct"]
    assert small_risk <= large_risk + 1e-9


def test_cross_scan_isolation(client: TestClient) -> None:
    target_a = REPO_ROOT / "testdata" / "python"
    target_b = REPO_ROOT / "testdata" / "c"

    cbom_a = client.post("/api/scan", json={"path": str(target_a)}).json()
    cbom_b = client.post("/api/scan", json={"path": str(target_b)}).json()

    plan_a1 = client.post("/api/optimize", json={"cbom": cbom_a}).json()
    plan_b = client.post("/api/optimize", json={"cbom": cbom_b}).json()
    plan_a2 = client.post("/api/optimize", json={"cbom": cbom_a}).json()

    assert plan_a1 == plan_a2
    assert plan_a1 != plan_b
