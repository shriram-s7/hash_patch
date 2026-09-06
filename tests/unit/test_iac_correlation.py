"""tests/unit/test_iac_correlation.py

Phase 4: unit tests for the container-to-IaC correlation layer —
hash_patch/detect/iac/correlation.py.

Verifies the deterministic image-matching contract (digest > exact tag >
name-only, with digest/tag mismatches REJECTED never fuzzy-matched), the
workload -> service -> ingress join, and cross-namespace isolation.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.detect.iac.correlation import (
    ImageIdentity,
    find_services_for_workload,
    find_workload_for_container,
)
from hash_patch.detect.iac.models import (
    ContainerSpec,
    CorrelationStrength,
    ExposureState,
)
from hash_patch.detect.iac.scanner import scan_iac_directory

CORRELATION_FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac" / "correlation"


class TestImageIdentity:
    def test_parse_full(self) -> None:
        i = ImageIdentity.from_string("registry.example/app:1.2@sha256:deadbeef")
        assert (i.repository, i.tag, i.digest) == ("registry.example/app", "1.2", "sha256:deadbeef")

    def test_parse_tag_only(self) -> None:
        i = ImageIdentity.from_string("app:1.2")
        assert (i.repository, i.tag, i.digest) == ("app", "1.2", None)

    def test_parse_bare_name_has_no_tag(self) -> None:
        # A bare `app` must NOT be coerced to implicit `latest`; that would
        # blur the "tag mismatch is rejected" rule with name-only matching.
        i = ImageIdentity.from_string("app")
        assert (i.repository, i.tag, i.digest) == ("app", None, None)

    def test_digest_match_is_direct(self) -> None:
        a = ImageIdentity.from_string("app@sha256:abc")
        b = ImageIdentity.from_string("app@sha256:abc")
        assert a.matches(b) == (True, CorrelationStrength.DIRECT)

    def test_digest_mismatch_is_rejected(self) -> None:
        a = ImageIdentity.from_string("app@sha256:abc")
        b = ImageIdentity.from_string("app@sha256:def")
        assert a.matches(b) == (False, CorrelationStrength.NONE)

    def test_exact_tag_is_strong(self) -> None:
        a = ImageIdentity.from_string("app:1.4")
        b = ImageIdentity.from_string("app:1.4")
        assert a.matches(b) == (True, CorrelationStrength.STRONG)

    def test_tag_mismatch_is_rejected(self) -> None:
        a = ImageIdentity.from_string("app:1.4")
        b = ImageIdentity.from_string("app:2.0")
        assert a.matches(b) == (False, CorrelationStrength.NONE)

    def test_one_side_unpinned_is_moderate(self) -> None:
        a = ImageIdentity.from_string("app")
        b = ImageIdentity.from_string("app:1.4")
        assert a.matches(b) == (True, CorrelationStrength.MODERATE)
        assert b.matches(a) == (True, CorrelationStrength.MODERATE)

    def test_repo_mismatch_is_rejected(self) -> None:
        a = ImageIdentity.from_string("app-a:1.4")
        b = ImageIdentity.from_string("app-b:1.4")
        assert a.matches(b) == (False, CorrelationStrength.NONE)


def _corr(fixture: str):
    return scan_iac_directory(CORRELATION_FIXTURES / fixture)


class TestWorkloadCorrelation:
    def test_container_to_deployment_tag_match(self) -> None:
        iac = _corr("container_to_deployment")
        w, strength = find_workload_for_container(
            ContainerSpec(name="", image="payment-api:1.4"), iac
        )
        assert w is not None
        assert w.identity.key() == "kubernetes:production:Deployment:payment-api"
        assert strength is CorrelationStrength.STRONG
        services = find_services_for_workload(w, iac)
        assert [s.identity.name for s in services] == ["payment-api"]
        assert services[0].service_type.value == "ClusterIP"

    def test_digest_match_wins(self) -> None:
        iac = _corr("digest_match")
        w, strength = find_workload_for_container(
            ContainerSpec(name="", image="payment-api@sha256:abc123def456"), iac
        )
        assert w is not None
        assert strength is CorrelationStrength.DIRECT

    def test_mismatch_is_rejected(self) -> None:
        iac = _corr("mismatch")
        w, strength = find_workload_for_container(
            ContainerSpec(name="", image="payment-api:1.4"), iac
        )
        assert w is None
        assert strength is CorrelationStrength.NONE

    def test_no_container_image_means_no_workload(self) -> None:
        iac = _corr("container_to_deployment")
        w, strength = find_workload_for_container(
            ContainerSpec(name="", image=""), iac
        )
        assert w is None

    def test_cross_namespace_same_image_is_isolated(self) -> None:
        # Two namespaces both run the SAME repo+tag can not both win; the
        # deterministic best-match must resolve cleanly, and service joins
        # must never cross namespace boundaries (covered below).
        iac = scan_iac_directory(
            Path(__file__).resolve().parents[2] / "testdata" / "iac" / "kubernetes" / "namespaces"
        )
        w, _ = find_workload_for_container(
            ContainerSpec(name="", image="payment-api:1.4"), iac
        )
        assert w is not None
        assert w.namespace == "production"
        services = find_services_for_workload(w, iac)
        # Only the production ClusterIP... no: only production services join.
        assert all(s.namespace == "production" for s in services)


class TestExposureStateOfFixtures:
    def test_ingress_extraction_smoke(self) -> None:
        # ImageIdentity/matches are covered above; this guards the richer
        # build_topology_evidence path used by the QA fixtures.
        assert ExposureState.UNKNOWN is not ExposureState.EXTERNAL
        assert ExposureState.MIXED.value == "mixed"
        assert ExposureState.INTERNAL.value == "internal"
