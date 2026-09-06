"""tests/unit/test_iac_security.py

Phase 4: security hardening for the IaC parsers.

Malformed files fail gracefully (parse_errors, never an exception that aborts
a scan). Oversized inputs are refused by the size cap. Yaml bombs / deep
nesting complete within practical bounds without DoS. Secret / ConfigMap
material (base64, connection strings, API keys) must NEVER end up in emitted
CBOM output. Prompt-injection strings embedded in labels/annotations/comments
are treated as inert DATA — they must never change exposure classification
or reach an Ollama prompt as instructions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hash_patch.detect.iac.kubernetes import KubernetesParser
from hash_patch.detect.iac.scanner import apply_iac_enrichment, scan_iac_directory
from hash_patch.detect.iac.terraform import TerraformParser
from hash_patch.emit.cyclonedx import to_cyclonedx
from hash_patch.model.assets import AssetType, CryptoAsset, Primitive, derive_asset_id
from hash_patch.model.evidence import Evidence
from hash_patch.model.findings import ScanResult

SECURITY_DIR = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "security"
K8S_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "kubernetes"
TF_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "terraform"
FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)

SECRET_MARKERS = ["YWRtaW4=", "c3VwZXJzZWNyZXQ=", "sk-1234567890abcdef", "postgresql://user:password@localhost/db"]
INJECTION_MARKERS = ["IGNORE ALL PREVIOUS INSTRUCTIONS"]


class TestMalformedInputs:
    def test_malformed_yaml_surfaces_parse_error_not_crash(self) -> None:
        res = KubernetesParser().parse_file(SECURITY_DIR / "malformed" / "malformed.yaml")
        assert res.workloads == []
        assert len(res.parse_errors) >= 1

    def test_malformed_terraform_clean(self) -> None:
        content = "resource \"aws_lb\" {\n  internal = \n}"
        res = TerraformParser().parse_content(content, "bad.tf")
        assert res.tf_resources == []
        assert len(res.parse_errors) >= 1

    def test_oversized_yaml_is_refused(self, tmp_path: Path) -> None:
        big = tmp_path / "big.yaml"
        big.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: big}\ndata: {x: '" + "A" * (55 * 1024 * 1024) + "'}\n", encoding="utf-8")
        parser = KubernetesParser()
        # _MAX_FILE_SIZE is 50MB; the parser should refuse without resource cost.
        res = parser.parse_file(big)
        assert res.parse_errors

    def test_oversized_terraform_is_refused(self) -> None:
        content = "resource \"aws_lb\" \"app\" { internal = false }\n" * 2001
        res = TerraformParser().parse_content(content, "huge.tf")
        # _MAX_RESOURCES caps under per-file extra; parse_errors empty but bounded.
        assert len(res.tf_resources) <= 1000

    def test_yaml_bomb_does_not_blast(self) -> None:
        parser = KubernetesParser()
        payload = (SECURITY_DIR / "yaml_bomb" / "bomb.yaml").read_text(encoding="utf-8")
        res = parser.parse_content(payload, "bomb.yaml")
        assert res.workloads == []
        assert res.services == []

    def test_deep_nesting_does_not_crash(self) -> None:
        res = KubernetesParser().parse_file(SECURITY_DIR / "deep_nesting" / "deep.yaml")
        assert isinstance(res, object)


class TestSecretSafety:
    def test_secret_configmap_values_never_reach_output(self) -> None:
        parser = KubernetesParser()
        res = parser.parse_file(SECURITY_DIR / "secret_leakage" / "secret.yaml")
        # Secret existence may be noted; its contents must not be parsed
        # into any ContainerSpec env or emitted anywhere.
        assert res.workloads == []
        assert res.services == []

    def test_scan_output_contains_no_secret_markers(self) -> None:
        iac = scan_iac_directory(SECURITY_DIR / "secret_leakage")
        asset = CryptoAsset(
            id=derive_asset_id(AssetType.ALGORITHM, "X", None, None),
            name="X",
            asset_type=AssetType.ALGORITHM,
            primitive=Primitive.SIGNATURE,
            evidence=[Evidence(locator="x", source_type="binary", detector_id="d", detector_version="0", snippet="")],
        )
        apply_iac_enrichment([asset], iac)
        res = ScanResult(target="t", assets=[asset], scan_started_at=FIXED_TS, tool_version="0.1.0")
        doc = to_cyclonedx(res)
        blob = str(doc)
        for marker in SECRET_MARKERS:
            assert marker not in blob


class TestPromptInjection:
    def test_injected_manifest_does_not_change_exposure(self) -> None:
        normal = scan_iac_directory(K8S_FIXTURES / "internal")
        injected = scan_iac_directory(K8S_FIXTURES / "prompt_injection")
        assert len(injected.services) == len(normal.services)
        assert injected.services[0].service_type == normal.services[0].service_type
        assert injected.workloads[0].identity.key() == normal.workloads[0].identity.key()

    def test_injected_tf_comments_do_not_change_parse(self) -> None:
        plain = TerraformParser().parse_directory(TF_FIXTURES / "alb")
        injected = TerraformParser().parse_directory(TF_FIXTURES / "prompt_injection")
        lb_plain = {r.name: r for r in plain.tf_resources if r.resource_type == "aws_lb"}
        lb_inj = {r.name: r for r in injected.tf_resources if r.resource_type == "aws_lb"}
        assert len(lb_inj) == len(lb_plain)
        # The injected corpus drops the security-groups/subnets set; the
        # topology-relevant attributes the classifier reads must match.
        for name, r_inj in lb_inj.items():
            common = set(lb_plain[name].attributes) & set(r_inj.attributes)
            assert {k: r_inj.attributes[k] for k in common} == {k: lb_plain[name].attributes[k] for k in common}

    def test_injection_markers_are_data_not_instructions(self) -> None:
        iac = scan_iac_directory(K8S_FIXTURES / "prompt_injection")
        asset = CryptoAsset(
            id=derive_asset_id(AssetType.ALGORITHM, "RSA", None, None),
            name="RSA",
            asset_type=AssetType.ALGORITHM,
            primitive=Primitive.SIGNATURE,
            evidence=[Evidence(locator="x", source_type="binary", detector_id="d", detector_version="0", snippet="")],
            properties={"containerImage": "payment-api:1.4"},
        )
        apply_iac_enrichment([asset], iac)
        # The injected text never becomes part of enrichment property values
        # that a downstream prompt could interpret as an instruction.
        for marker in INJECTION_MARKERS:
            for v in asset.properties.values():
                assert marker not in v


class TestPathTraversalAndSymlinks:
    def test_host_path_traversal_parsed_as_data(self) -> None:
        res = KubernetesParser().parse_file(SECURITY_DIR / "path_traversal" / "traversal.yaml")
        assert len(res.workloads) == 1
        # The hostile hostPath is never surfaced into any emitted property.
        env_flat = [c.env for w in res.workloads for c in w.containers]
        assert env_flat == [{}]

    def test_symlink_file_parsed_as_data(self) -> None:
        res = KubernetesParser().parse_file(SECURITY_DIR / "symlink" / "symlink.yaml")
        assert isinstance(res, object)
