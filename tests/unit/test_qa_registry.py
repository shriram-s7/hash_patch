"""tests/unit/test_qa_registry.py — Tests for ScanRegistry and normalized scan resolution."""

from __future__ import annotations

import pytest

from hash_patch.qa.registry import ScanRegistry


@pytest.fixture
def registry() -> ScanRegistry:
    reg = ScanRegistry()
    return reg


def test_register_scan_with_serial_number(registry: ScanRegistry) -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "components": [{"name": "RSA", "type": "cryptographic-asset"}],
    }
    rec = registry.register_scan(cbom)
    assert rec.serial_number == "urn:uuid:11111111-2222-3333-4444-555555555555"
    assert rec.scan_id == "urn:uuid:11111111-2222-3333-4444-555555555555"
    assert registry.get_latest_scan() == rec

    # Resolve by scan_id
    assert registry.get_scan(rec.scan_id) == rec
    # Resolve by serial_number
    assert registry.get_scan("urn:uuid:11111111-2222-3333-4444-555555555555") == rec


def test_register_scan_explicit_scan_id_decoupled_from_serial(registry: ScanRegistry) -> None:
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:aaaa-bbbb-cccc",
        "components": [],
    }
    rec = registry.register_scan(cbom, scan_id="custom_scan_001")
    assert rec.scan_id == "custom_scan_001"
    assert rec.serial_number == "urn:uuid:aaaa-bbbb-cccc"

    # Resolvable by custom scan_id
    assert registry.get_scan("custom_scan_001") == rec
    # Also resolvable by serialNumber lookup
    assert registry.get_scan("urn:uuid:aaaa-bbbb-cccc") == rec


def test_unknown_scan_id_returns_none(registry: ScanRegistry) -> None:
    # Must never return another scan
    cbom = {"serialNumber": "urn:uuid:real-scan", "components": []}
    registry.register_scan(cbom)

    assert registry.get_scan("nonexistent-scan-id") is None


def test_conversation_context_scoped_to_scan(registry: ScanRegistry) -> None:
    # Two different scans
    s1 = registry.register_scan({"serialNumber": "urn:uuid:scan-1", "components": []})
    s2 = registry.register_scan({"serialNumber": "urn:uuid:scan-2", "components": []})

    conv1 = registry.get_conversation(s1.scan_id, "conv-alpha")
    conv2 = registry.get_conversation(s2.scan_id, "conv-alpha")

    # Same conversation ID, but different scans -> isolated contexts
    assert conv1 is not conv2
    conv1.active_findings = ["RSA"]
    assert conv2.active_findings == []
