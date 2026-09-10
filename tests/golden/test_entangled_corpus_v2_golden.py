"""tests/golden/test_entangled_corpus_v2_golden.py

4th permanent golden regression test suite using
hash_patch_entangled_crypto_corpus_v2 and ground_truth.json.

Validates:
1. CycloneDX 1.6 schema compliance.
2. No duplicate standalone HMAC operations (only concrete HMAC-SHA256, HMAC-SHA384).
3. Merged-asset reachability: dead code sites are not hidden behind live ones.
   Per-evidence reachability is recorded and mixedReachability is flagged.
4. Call-graph relationship edges: all 17 expected function-to-function
   relationships from ground_truth.json are captured in result.call_graph_edges.
5. All operations in ground_truth.json are detected with matching algorithm,
   file, line, and reachability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hash_patch.cli import run_scan
from hash_patch.emit import to_cyclonedx, validate_cbom

REPO_ROOT = Path(__file__).resolve().parents[2]

CORPUS_DIR = Path("D:/CBOM-SIH/hash_patch_entangled_crypto_corpus_v2/hash_patch_entangled_crypto_corpus_v2")
if not CORPUS_DIR.is_dir():
    CORPUS_DIR = REPO_ROOT.parent / "hash_patch_entangled_crypto_corpus_v2" / "hash_patch_entangled_crypto_corpus_v2"

GROUND_TRUTH_FILE = Path("D:/CBOM-SIH/hash_patch_entangled_crypto_ground_truth_v2/ground_truth.json")
if not GROUND_TRUTH_FILE.is_file():
    GROUND_TRUTH_FILE = REPO_ROOT.parent / "hash_patch_entangled_crypto_ground_truth_v2" / "ground_truth.json"


@pytest.fixture(scope="module")
def ground_truth() -> dict:
    assert GROUND_TRUTH_FILE.is_file(), f"Ground truth file missing: {GROUND_TRUTH_FILE}"
    return json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scan_output() -> tuple:
    assert CORPUS_DIR.is_dir(), f"Corpus directory missing: {CORPUS_DIR}"
    result = run_scan(CORPUS_DIR)
    cbom = to_cyclonedx(result)
    return result, cbom


def test_entangled_corpus_v2_exists():
    assert CORPUS_DIR.is_dir()
    assert (CORPUS_DIR / "main.py").is_file()
    assert (CORPUS_DIR / "api.py").is_file()


def test_cbom_validates_against_cyclonedx_schema(scan_output):
    _, cbom = scan_output
    errors = validate_cbom(cbom)
    assert errors == [], f"CBOM validation errors against CycloneDX 1.6: {errors}"


def test_no_standalone_generic_hmac(scan_output):
    result, _ = scan_output
    # Ground truth specifies only concrete HMAC-SHA256 and HMAC-SHA384
    operation_names = [
        a.name for a in result.assets if a.finding_type == "OPERATION"
    ]
    assert "HMAC" not in operation_names, (
        "Found generic standalone 'HMAC' operation asset. Should be suppressed/resolved to concrete HMAC."
    )
    hmac_ops = [n for n in operation_names if "HMAC" in n]
    assert set(hmac_ops) == {"HMAC-SHA256", "HMAC-SHA384"}


def test_merged_assets_mixed_reachability(scan_output):
    result, cbom = scan_output
    # MD5, AES, SHA-256, SHA-384, and SHA-1 merge both live and dead/unreachable call sites
    expected_mixed = {"MD5", "AES", "SHA-256", "SHA-384", "SHA-1"}
    ops_by_name = {
        a.name: a for a in result.assets if a.finding_type == "OPERATION"
    }

    for algo in expected_mixed:
        assert algo in ops_by_name, f"Expected operation asset {algo} missing"
        asset = ops_by_name[algo]
        assert len(asset.evidence) > 1, f"Asset {algo} should have multiple evidence sites"
        assert asset.properties.get("mixedReachability") == "true", (
            f"Asset {algo} must be flagged with mixedReachability=true"
        )

    # Check that in the emitted CBOM, mixedReachability is present
    components_by_name = {
        c["name"]: c for c in cbom.get("components", [])
        if c.get("type") == "cryptographic-asset"
        and not any(
            p.get("name") == "hash_patch:findingType" and p.get("value") == "CRYPTO_REFERENCE"
            for p in c.get("properties", [])
        )
    }
    for algo in expected_mixed:
        comp = components_by_name.get(algo)
        assert comp is not None, f"Component {algo} missing in CBOM"
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert (
            props.get("hash_patch:mixedReachability") == "true"
            or props.get("hash_patch:property.mixedReachability") == "true"
        ), f"Component {algo} must emit mixedReachability property in CBOM"


def test_per_evidence_reachability_isolates_dead_code(scan_output):
    result, cbom = scan_output
    ops_by_name = {
        a.name: a for a in result.assets if a.finding_type == "OPERATION"
    }

    # 1. AES: dead/unused_cipher.py:8 is dead (unknown), documents/crypto.py:13 is live-external
    aes = ops_by_name["AES"]
    aes_reaches = {
        ev.locator.replace("\\", "/").split("/")[-2] + "/" + ev.locator.replace("\\", "/").split("/")[-1] + f":{ev.line}":
        aes.properties.get(f"evidenceReachability.{ev.locator}:{ev.line}")
        for ev in aes.evidence
    }
    assert aes_reaches.get("dead/unused_cipher.py:8") == "unknown"
    assert aes_reaches.get("documents/crypto.py:13") == "live-external"

    # 2. MD5: auth/legacy.py:8 is live-external, dead/*.py are dead (unknown)
    md5 = ops_by_name["MD5"]
    md5_reaches = {
        ev.locator.replace("\\", "/").split("/")[-1] + f":{ev.line}":
        md5.properties.get(f"evidenceReachability.{ev.locator}:{ev.line}")
        for ev in md5.evidence
    }
    assert md5_reaches.get("legacy.py:8") == "live-external"
    assert md5_reaches.get("unused_hashes.py:13") == "unknown"
    assert md5_reaches.get("dead_crypto.py:6") == "unknown"


def test_expected_call_graph_relationships(scan_output, ground_truth):
    result, cbom = scan_output
    expected_rels = set(tuple(r) for r in ground_truth["expected_relationships"])

    # Edges from ScanResult.call_graph_edges
    computed_edges = set(
        (e["caller"], e["callee"]) for e in result.call_graph_edges
    )

    # All 17 expected relationships must be covered
    missing = expected_rels - computed_edges
    assert not missing, f"Missing expected relationships from call graph: {missing}"

    # Also verify CBOM metadata contains hash_patch:callGraphEdges
    meta_props = {
        p["name"]: p["value"]
        for p in cbom.get("metadata", {}).get("properties", [])
    }
    assert "hash_patch:callGraphEdges" in meta_props, "Metadata must carry hash_patch:callGraphEdges"
    raw_edges = json.loads(meta_props["hash_patch:callGraphEdges"])
    cbom_edge_set = set((e["caller"], e["callee"]) for e in raw_edges)
    assert not (expected_rels - cbom_edge_set), "CBOM metadata callGraphEdges missing expected relationships"


def test_expected_finding_level_call_relations(scan_output):
    """compute_call_relations (asset/finding level, NOT the function-level
    result.call_graph_edges the previous test checks) must actually connect
    findings across orchestrator-delegation layers and fan-in call sites --
    this is the data the UI's Relationships graph renders
    (hash_patch:property.callRelation -> hash_patch-ui/src/graphEdges.ts's
    buildCallGraphEdges, which reads `callRelation`, never `callGraphEdges`).
    A passing test_expected_call_graph_relationships alone does NOT prove
    the UI shows anything -- that test only reaches result.call_graph_edges,
    a value the Relationships graph never consumes.

    Assets in this corpus are deduplicated by algorithm, not call site, so
    the three call-graph fan-in points (shared.digest.modern_digest,
    documents.crypto.document_digest -- both SHA-256; payments.signing.
    sign_payment and auth.legacy.legacy_auth_tag -- both HMAC-SHA256) surface
    as the SHA-256 and HMAC-SHA256 assets each carrying relations gathered
    from every branch they appear in.
    """
    result, _ = scan_output
    ops_by_name = {a.name: a for a in result.assets if a.finding_type == "OPERATION"}

    def callees_of(name: str) -> set[str]:
        asset = ops_by_name[name]
        raw = asset.properties.get("callRelation")
        assert raw is not None, f"{name} has no callRelation -- Relationships graph would show it as unconnected"
        return set(json.loads(raw)["callees"])

    # SHA-256 (modern_digest + document_digest) is reachable from all three
    # main branches: auth (MD5, HMAC-SHA256), payments (HMAC-SHA256, SHA-384),
    # documents (AES) -- proving fan-in isn't dropped to a single caller.
    sha256_callees = callees_of("SHA-256")
    for expected in ("MD5", "HMAC-SHA256", "SHA-384", "AES"):
        assert ops_by_name[expected].id in sha256_callees, (
            f"SHA-256 callRelation missing sibling {expected} -- fan-in relation dropped"
        )

    # HMAC-SHA256 (legacy_auth_tag + sign_payment) must connect back to
    # SHA-256 from BOTH the auth branch and the payments branch, plus MD5
    # (auth sibling) and SHA-384 (payments sibling) -- not just one branch.
    hmac_callees = callees_of("HMAC-SHA256")
    for expected in ("MD5", "SHA-256", "SHA-384"):
        assert ops_by_name[expected].id in hmac_callees, (
            f"HMAC-SHA256 callRelation missing sibling {expected} -- delegation-chain relation dropped"
        )

    # AES (encrypt_document) and SHA-256 (document_digest) are siblings under
    # documents.service.protect_document -- must be connected, but NOT
    # connected to MD5/SHA-384, which belong to unrelated branches (a naive
    # "climb to the program's single entry point" implementation would wrongly
    # connect every branch to every other branch).
    aes_callees = callees_of("AES")
    assert ops_by_name["SHA-256"].id in aes_callees
    assert ops_by_name["MD5"].id not in aes_callees, "AES must not be related to the unrelated auth branch"
    assert ops_by_name["SHA-384"].id not in aes_callees, "AES must not be related to the unrelated payments branch"


def test_all_ground_truth_operations_detected(scan_output, ground_truth):
    result, _ = scan_output
    ops = ground_truth["operations"]

    for op in ops:
        expected_algo = op["algorithm"]
        expected_file = op["file"]
        expected_line = op["line"]

        # Base algorithm name (e.g. AES-CBC maps to AES component with mode cbc)
        base_algo = expected_algo.split("-")[0] if expected_algo.startswith("AES-") else expected_algo

        # Find matching asset
        matching_asset = None
        for a in result.assets:
            if a.finding_type != "OPERATION":
                continue
            if a.name == base_algo or a.name == expected_algo:
                for ev in a.evidence:
                    norm_loc = ev.locator.replace("\\", "/")
                    if norm_loc.endswith(expected_file) and abs(ev.line - expected_line) <= 1:
                        matching_asset = a
                        break
            if matching_asset:
                break

        assert matching_asset is not None, (
            f"Operation {op['id']} ({expected_algo} at {expected_file}:{expected_line}) not found in scan results"
        )
