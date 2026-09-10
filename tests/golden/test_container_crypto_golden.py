"""Golden tests for Container Image Cryptographic Artefact Scanning (Phase 3).
Verifies:
1. Exact findings and provenance for source_crypto fixture
2. Exact findings and provenance for binary_crypto fixture
3. Exact findings and provenance for cloud_kms fixture
4. Coexistence without collision in mixed fixture
5. Layered replacement semantics (layer 2 replaces layer 1 file)
6. Whiteout semantics (layer 2 .wh. file deletes layer 1 binary from final image)
7. Negative fixture producing zero false positives
8. Exact CycloneDX CBOM properties emission
9. Reachability defaults to unknown and no fabricated runtime execution
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.analyze.cbom_reader import read_candidates
from hash_patch.cli import run_scan
from hash_patch.detect.container import scan_container_image
from hash_patch.emit.cyclonedx import render_cbom_json, to_cyclonedx

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "testdata" / "containers"


class TestContainerCryptoGolden:
    def test_source_crypto_fixture(self) -> None:
        target = FIXTURES_DIR / "source_crypto" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "source-crypto:1.0"
        assert len(res.assets) == 2

        names = {a.name for a in res.assets}
        assert "AES" in names
        assert "SHA-256" in names

        for asset in res.assets:
            assert asset.properties["containerImage"] == "source-crypto:1.0"
            assert asset.properties["pathInsideContainer"] == "/app/service.py"
            assert asset.properties["effectiveFs"] == "true"
            assert asset.reachability.value == "unknown"
            assert "Cryptographic operation observed" in asset.properties["honestFraming"]
            assert asset.evidence[0].locator.startswith("container://source-crypto:1.0@")

    def test_binary_crypto_fixture(self) -> None:
        target = FIXTURES_DIR / "binary_crypto" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "binary-crypto:1.0"
        assert len(res.assets) == 9

        # Verify RSA symbol finding
        rsa_assets = [a for a in res.assets if a.name == "RSA"]
        assert len(rsa_assets) >= 1
        rsa = rsa_assets[0]
        assert rsa.properties["binaryFormat"] == "ELF"
        assert rsa.properties["containerImage"] == "binary-crypto:1.0"
        assert rsa.properties["pathInsideContainer"] == "/usr/bin/server"
        assert rsa.properties["verificationScope"] == "container_binary_observation"
        assert rsa.reachability.value == "unknown"

        # Verify libcrypto linked library finding
        lib_assets = [a for a in res.assets if a.properties.get("evidenceType") == "linked_library"]
        assert len(lib_assets) >= 1
        lib = lib_assets[0]
        assert lib.properties["algorithm"] == "unknown"
        assert lib.quantum_status.value == "unknown"

    def test_cloud_kms_fixture(self) -> None:
        target = FIXTURES_DIR / "cloud_kms" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "cloud-kms:1.0"
        assert len(res.assets) == 2

        ops = {a.properties.get("operation") for a in res.assets}
        assert "encrypt" in ops
        assert "decrypt" in ops

        for a in res.assets:
            assert a.properties["containerImage"] == "cloud-kms:1.0"
            assert a.properties["pathInsideContainer"] == "/app/cloud_service.py"
            assert a.properties["verificationScope"] == "container_cloud_kms_call"
            assert a.reachability.value == "unknown"
            assert a.quantum_status.value == "algorithm-opaque-provider-managed"

    def test_mixed_fixture_coexistence(self) -> None:
        target = FIXTURES_DIR / "mixed" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "mixed-service:2.0"
        assert len(res.assets) == 13

        # Distinct sources coexisting
        types = {a.finding_type for a in res.assets}
        assert "OPERATION" in types
        assert "COMPILED_CRYPTO_ARTEFACT" in types
        assert "CLOUD_KEY_OPERATION" in types

        # Check file paths inside container
        paths = {a.properties["pathInsideContainer"] for a in res.assets}
        assert "/app/service.py" in paths
        assert "/app/cloud_service.py" in paths
        assert "/usr/bin/server" in paths

    def test_layered_replacement_semantics(self) -> None:
        target = FIXTURES_DIR / "layered" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "layered-app:1.0"
        # Layer 2 replaced Layer 1's sha256 with sha512
        assert len(res.assets) == 1
        assert res.assets[0].name == "SHA-512"

    def test_whiteout_deletion_semantics(self) -> None:
        target = FIXTURES_DIR / "whiteout" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "whiteout-app:1.0"
        # Layer 1 had crypto binary, Layer 2 deleted it via .wh.crypto_server
        assert len(res.assets) == 0
        assert "/usr/bin/crypto_server" in res.effective_fs.deleted_files

    def test_negative_fixture(self) -> None:
        target = FIXTURES_DIR / "negative" / "container.tar"
        res = scan_container_image(target)

        assert res.metadata.repo_tag == "clean-app:1.0"
        # Benign names (keyboard, userKey, encryptButton) must produce 0 crypto findings
        assert len(res.assets) == 0

    def test_cbom_emission_golden(self) -> None:
        target = FIXTURES_DIR / "mixed" / "container.tar"
        scan_res = run_scan(target)
        doc = to_cyclonedx(scan_res)
        cbom_json = render_cbom_json(doc)

        assert "hash_patch:property.containerImage" in cbom_json
        assert "mixed-service:2.0" in cbom_json
        assert "hash_patch:property.layerDigest" in cbom_json
        assert "hash_patch:property.pathInsideContainer" in cbom_json
        assert "/usr/bin/server" in cbom_json
        assert "hash_patch:property.effectiveFs" in cbom_json
        assert "hash_patch:reachability" in cbom_json

    def test_mixed_fixture_migration_candidates(self) -> None:
        """Regression guard: RSA/ECDSA (COMPILED_CRYPTO_ARTEFACT, broken-by-
        shor) must appear as Pillar 5 migration candidates with the
        binary_artefact_default cost fallback -- not silently excluded the
        way a CERTIFICATE/CRYPTO_REFERENCE finding correctly is. Before this
        fallback existed, real Shor-broken findings from binary/container
        scans never appeared in any migration plan at all.
        """
        target = FIXTURES_DIR / "mixed" / "container.tar"
        scan_res = run_scan(target)
        doc = to_cyclonedx(scan_res)

        candidates, excluded_count = read_candidates(doc)

        candidates_by_name = {c.name: c for c in candidates}
        for algo in ("RSA", "ECDSA"):
            assert algo in candidates_by_name, f"{algo} missing from migration candidates"
            candidate = candidates_by_name[algo]
            assert candidate.cost_source == "binary_artefact_default"
            assert candidate.cost_days == 0.5
            assert candidate.risk_score > 0

        # Every OTHER component in this fixture (AES/SHA-256 weakened-by-
        # grover, Kyber quantum-safe, the AWS KMS ops, the embedded
        # certificate, OpenSSL/libcrypto linkage, ...) is correctly still
        # excluded -- this fallback is additive, not a blanket bypass.
        assert excluded_count == len(scan_res.assets) - 2
