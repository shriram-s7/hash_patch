from __future__ import annotations

import random
from datetime import UTC, datetime

from pratyaksha.model.assets import AssetType, CryptoAsset, Primitive
from pratyaksha.model.evidence import Evidence
from pratyaksha.model.findings import ScanResult


def _evidence(locator: str, line: int) -> Evidence:
    return Evidence(
        source_type="source",
        locator=locator,
        line=line,
        column=1,
        byte_offset=None,
        snippet="RSA.generate(2048)",
        detector_id="test-detector",
        detector_version="0.1.0",
    )


def test_crypto_asset_id_is_stable() -> None:
    a1 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
    )
    a2 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
    )
    assert a1.id == a2.id
    assert a1.id.startswith("crypto-asset:")


def test_scan_result_add_asset_merges_duplicates_and_unions_evidence() -> None:
    result = ScanResult(
        target="testdata/sample",
        scan_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        tool_version="0.1.0",
    )

    asset1 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
        evidence=[_evidence("a.py", 10)],
    )
    asset2 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
        evidence=[_evidence("b.py", 20)],
    )

    result.add_asset(asset1)
    result.add_asset(asset2)

    assert len(result.assets) == 1
    merged = result.assets[0]
    assert len(merged.evidence) == 2
    locators = {e.locator for e in merged.evidence}
    assert locators == {"a.py", "b.py"}


def test_scan_result_add_asset_does_not_duplicate_identical_evidence() -> None:
    result = ScanResult(
        target="testdata/sample",
        scan_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        tool_version="0.1.0",
    )
    asset1 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
        evidence=[_evidence("a.py", 10)],
    )
    asset2 = CryptoAsset.create(
        asset_type=AssetType.ALGORITHM,
        name="RSA",
        primitive=Primitive.SIGNATURE,
        parameter_set="2048",
        mode=None,
        evidence=[_evidence("a.py", 10)],
    )
    result.add_asset(asset1)
    result.add_asset(asset2)
    assert len(result.assets[0].evidence) == 1


def test_sorted_assets_is_deterministic_across_shuffled_input_order() -> None:
    names = ["RSA", "AES", "ECDSA", "SHA-256", "ChaCha20"]
    assets = [
        CryptoAsset.create(
            asset_type=AssetType.ALGORITHM,
            name=name,
            primitive=Primitive.OTHER,
            parameter_set=None,
            mode=None,
        )
        for name in names
    ]

    shuffled_once = list(assets)
    random.Random(1).shuffle(shuffled_once)
    shuffled_twice = list(assets)
    random.Random(42).shuffle(shuffled_twice)

    result_a = ScanResult(
        target="t",
        scan_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        tool_version="0.1.0",
    )
    for asset in shuffled_once:
        result_a.add_asset(asset)

    result_b = ScanResult(
        target="t",
        scan_started_at=datetime(2026, 1, 1, tzinfo=UTC),
        tool_version="0.1.0",
    )
    for asset in shuffled_twice:
        result_b.add_asset(asset)

    ids_a = [a.id for a in result_a.sorted_assets()]
    ids_b = [a.id for a in result_b.sorted_assets()]
    assert ids_a == ids_b
    assert ids_a == sorted(ids_a)
