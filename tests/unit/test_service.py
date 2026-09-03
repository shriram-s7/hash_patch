from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hash_patch.analyze.cbom_reader import read_candidates, read_reference_year
from hash_patch.analyze.optimizer import run_optimizer
from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx, validate_cbom
from hash_patch.service import app

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_real_directory(client: TestClient) -> None:
    target_dir = REPO_ROOT / "testdata" / "python"
    response = client.post("/api/scan", json={"path": str(target_dir)})

    assert response.status_code == 200
    cbom_data = response.json()

    # Validate against CycloneDX 1.6 schema
    validation_errors = validate_cbom(cbom_data)
    assert validation_errors == [], f"Emitted CBOM failed schema validation: {validation_errors}"

    # Compare against direct run_scan() call
    direct_result = run_scan(target_dir)
    direct_cbom = to_cyclonedx(direct_result)

    assert cbom_data["bomFormat"] == "CycloneDX"
    assert cbom_data["specVersion"] == "1.6"
    assert cbom_data["serialNumber"] == direct_cbom["serialNumber"]
    assert cbom_data["components"] == direct_cbom["components"]


def test_scan_nonexistent_path_returns_400(client: TestClient) -> None:
    response = client.post("/api/scan", json={"path": "nonexistent/path/does/not/exist/ever"})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body
    assert "does not exist" in body["detail"].lower()


def test_scan_file_path_returns_400(client: TestClient) -> None:
    file_path = REPO_ROOT / "pyproject.toml"
    response = client.post("/api/scan", json={"path": str(file_path)})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body
    assert "is not a directory" in body["detail"].lower()


def test_scan_empty_path_returns_400(client: TestClient) -> None:
    response = client.post("/api/scan", json={"path": ""})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body


def test_optimize_matches_direct_run_optimizer(client: TestClient) -> None:
    target_dir = REPO_ROOT / "testdata" / "python"
    cbom_data = to_cyclonedx(run_scan(target_dir))

    response = client.post(
        "/api/optimize",
        json={"cbom": cbom_data, "budget_days": 5.0, "parallelism": 1},
    )
    assert response.status_code == 200
    report = response.json()

    candidates, excluded_count = read_candidates(cbom_data)
    reference_year = read_reference_year(cbom_data)
    direct_report = run_optimizer(
        candidates,
        budget_days=5.0,
        parallelism=1,
        reference_year=reference_year,
        excluded_count=excluded_count,
    ).model_dump(mode="json")

    assert report == direct_report
    assert report["candidate_count"] == len(candidates)
    assert report["excluded_count"] == excluded_count
    for scenario in report["scenarios"]:
        assert 0.0 <= scenario["optimizer_plan"]["risk_eliminated_pct"] <= 100.0


def test_optimize_uses_default_budget_and_parallelism(client: TestClient) -> None:
    target_dir = REPO_ROOT / "testdata" / "python"
    cbom_data = to_cyclonedx(run_scan(target_dir))

    response = client.post("/api/optimize", json={"cbom": cbom_data})
    assert response.status_code == 200
    report = response.json()
    assert report["budget_days"] == 5.0
    assert report["parallelism"] == 1


def test_optimize_missing_cbom_returns_400(client: TestClient) -> None:
    response = client.post("/api/optimize", json={"budget_days": 5.0, "parallelism": 1})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body
    assert "cbom" in body["detail"].lower()


def test_optimize_invalid_budget_days_returns_400(client: TestClient) -> None:
    cbom_data = to_cyclonedx(run_scan(REPO_ROOT / "testdata" / "python"))
    response = client.post("/api/optimize", json={"cbom": cbom_data, "budget_days": 0})
    assert response.status_code == 400


def test_optimize_invalid_parallelism_returns_400(client: TestClient) -> None:
    cbom_data = to_cyclonedx(run_scan(REPO_ROOT / "testdata" / "python"))
    response = client.post("/api/optimize", json={"cbom": cbom_data, "parallelism": 0})
    assert response.status_code == 400


def test_optimize_cbom_without_timestamp_returns_400(client: TestClient) -> None:
    cbom_data = to_cyclonedx(run_scan(REPO_ROOT / "testdata" / "python"))
    del cbom_data["metadata"]["timestamp"]
    response = client.post("/api/optimize", json={"cbom": cbom_data})
    assert response.status_code == 400
    body = response.json()
    assert "detail" in body


def test_cors_headers_allowed_origins(client: TestClient) -> None:
    for allowed_origin in ["http://localhost:5173", "http://localhost:5174"]:
        resp = client.get("/api/health", headers={"Origin": allowed_origin})
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == allowed_origin

        # Test preflight OPTIONS request
        options_resp = client.options(
            "/api/scan",
            headers={
                "Origin": allowed_origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert options_resp.status_code == 200
        assert options_resp.headers.get("access-control-allow-origin") == allowed_origin


def test_cors_headers_disallowed_origin(client: TestClient) -> None:
    disallowed_origin = "http://malicious-site.example.com"
    resp = client.get("/api/health", headers={"Origin": disallowed_origin})
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") != disallowed_origin

    options_resp = client.options(
        "/api/scan",
        headers={
            "Origin": disallowed_origin,
            "Access-Control-Request-Method": "POST",
        },
    )
    assert options_resp.headers.get("access-control-allow-origin") != disallowed_origin
