"""tests/unit/test_call_relations.py

Unit tests for hash_patch/analyze/call_relations.py — the caller/callee edge
extraction feeding the UI's "Asset Relationships" graph.

Runs the real CLI scan path (hash_patch.cli.run_scan) over
testdata/python/call_chain_example.py (a deliberately deep, 6-level call
chain SHA-512 -> RSA -> MD5, each pair connected by a DIRECT call edge — see
that file's own docstring) and asserts on the
`hash_patch:property.callRelation` value attached to each of the three
findings, so the edges are regression-tested against the real property shape
the emitted CBOM carries, not just the in-memory dict.
"""

from __future__ import annotations

import json
from pathlib import Path

from hash_patch.cli import run_scan
from hash_patch.model.assets import CryptoAsset

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_PY_DIR = REPO_ROOT / "testdata" / "python"


def _asset_for(assets: list[CryptoAsset], algorithm: str, locator_suffix: str) -> CryptoAsset | None:
    for asset in assets:
        if asset.name != algorithm:
            continue
        for ev in asset.evidence:
            if ev.locator.replace("\\", "/").endswith(locator_suffix):
                return asset
    return None


def _call_relation(asset: CryptoAsset) -> dict[str, list[str]] | None:
    raw = asset.properties.get("callRelation")
    if raw is None:
        return None
    return json.loads(raw)


def _chain_assets(result) -> tuple[CryptoAsset, CryptoAsset, CryptoAsset]:
    sha512 = _asset_for(result.assets, "SHA-512", "call_chain_example.py")
    rsa_asset = _asset_for(result.assets, "RSA", "call_chain_example.py")
    md5 = _asset_for(result.assets, "MD5", "call_chain_example.py")
    assert sha512 is not None, "SHA-512 finding not found in call_chain_example.py"
    assert rsa_asset is not None, "RSA finding not found in call_chain_example.py"
    assert md5 is not None, "MD5 finding not found in call_chain_example.py"
    return sha512, rsa_asset, md5


def test_sha512_callee_edge_points_at_rsa() -> None:
    """level_2() (SHA-512) directly calls level_4() (RSA) -- a real,
    one-hop call-graph edge -- so SHA-512's callRelation.callees must list
    the RSA finding's asset id.
    """
    result = run_scan(TESTDATA_PY_DIR)
    sha512, rsa_asset, _md5 = _chain_assets(result)

    rel = _call_relation(sha512)
    assert rel is not None, "SHA-512 finding should carry a hash_patch:property.callRelation"
    assert rsa_asset.id in rel["callees"]
    assert rel["callers"] == []


def test_rsa_has_both_a_caller_and_a_callee_edge() -> None:
    """RSA sits in the middle of the chain: level_2 (SHA-512) calls level_4
    (RSA) directly, and level_4 calls level_6_leaf (MD5) directly. So RSA's
    callRelation must show SHA-512 as a caller and MD5 as a callee.
    """
    result = run_scan(TESTDATA_PY_DIR)
    sha512, rsa_asset, md5 = _chain_assets(result)

    rel = _call_relation(rsa_asset)
    assert rel is not None, "RSA finding should carry a hash_patch:property.callRelation"
    assert rel["callers"] == [sha512.id]
    assert rel["callees"] == [md5.id]


def test_md5_caller_edge_points_at_rsa() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    _sha512, rsa_asset, md5 = _chain_assets(result)

    rel = _call_relation(md5)
    assert rel is not None, "MD5 finding should carry a hash_patch:property.callRelation"
    assert rel["callers"] == [rsa_asset.id]
    assert rel["callees"] == []


def test_call_relations_never_link_findings_with_no_direct_call_edge() -> None:
    """A finding elsewhere in the corpus (unrelated in the call graph, and a
    genuinely distinct algorithm/asset so it can't be the same merged
    CryptoAsset as any chain member) must never show up in this chain's
    relations, even though a real scan sees every testdata file at once.
    """
    result = run_scan(TESTDATA_PY_DIR)
    sha512, rsa_asset, md5 = _chain_assets(result)
    unrelated_external = _asset_for(result.assets, "SHA3-256", "reachability_live_internal.py")
    assert unrelated_external is not None

    for asset in (sha512, rsa_asset, md5):
        rel = _call_relation(asset)
        if rel is None:
            continue
        assert unrelated_external.id not in rel["callers"]
        assert unrelated_external.id not in rel["callees"]
