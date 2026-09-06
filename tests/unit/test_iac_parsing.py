"""tests/unit/test_iac_parsing.py

Phase 4: unit tests for the IaC topology parsers —
hash_patch/detect/iac/{kubernetes,terraform}.py.

Covers Kubernetes Deployments/StatefulSets/DaemonSets/Services/Ingresses/
Gateways/HTTPRoutes and Terraform aws_lb/alb/api_gateway/cloudfront resources,
including the deterministic resource-identity contract, HCL quote handling
(python-hcl2 wraps keys/values in quotes), and the exposure-relevant attribute
extraction. Security hardening (bombs/malformed/huge/secret) lives in
test_iac_security.py.
"""

from __future__ import annotations

from pathlib import Path

from hash_patch.detect.iac.kubernetes import KubernetesParser
from hash_patch.detect.iac.models import IacType, ServiceType
from hash_patch.detect.iac.terraform import TerraformParser

FIXTURES = Path(__file__).resolve().parents[2] / "testdata" / "iac"


# ===========================================================================
# Kubernetes parsing
# ===========================================================================


def _parse_k8s(fixture: str) -> object:
    return KubernetesParser().parse_file(FIXTURES / "kubernetes" / fixture / "deployment.yaml")


class TestKubernetesParsing:
    def test_deployment_identity_and_containers(self) -> None:
        res = _parse_k8s("internal")
        assert len(res.workloads) == 1
        w = res.workloads[0]
        assert w.identity.iac_type is IacType.KUBERNETES
        assert w.identity.kind == "Deployment"
        assert w.identity.name == "payment-api"
        assert w.identity.namespace == "production"
        assert w.identity.key() == "kubernetes:production:Deployment:payment-api"
        assert w.selector == {"app": "payments"}
        assert len(w.containers) == 1
        assert w.containers[0].image == "payment-api:1.4"
        assert w.containers[0].ports == [8080]

    def test_service_types(self) -> None:
        assert [s.service_type for s in _parse_k8s("internal").services] == [ServiceType.CLUSTER_IP]
        assert [s.service_type for s in _parse_k8s("loadbalancer").services] == [ServiceType.LOAD_BALANCER]

    def test_ingress_rules_and_backend(self) -> None:
        res = _parse_k8s("ingress")
        assert len(res.ingresses) == 1
        ing = res.ingresses[0]
        assert ing.identity.name == "payments"
        assert ing.identity.namespace == "production"
        assert len(ing.rules) == 1
        assert ing.rules[0].host == "payments.example.com"
        assert ing.rules[0].paths[0].backend.service_name == "payment-api"

    def test_nodeport_is_mixed_eligible(self) -> None:
        # NodePort services are never assumed internal
        content = (
            "apiVersion: v1\nkind: Service\nmetadata: {name: x, namespace: default}\n"
            "spec: {type: NodePort, selector: {app: x}, ports: [{port: 80}]}\n"
        )
        res = KubernetesParser().parse_content(content, "nodeport.yaml")
        assert res.services[0].service_type is ServiceType.NODE_PORT

    def test_gateway_listener(self) -> None:
        content = """apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: gateway
  namespace: production
spec:
  listeners:
  - name: http
    protocol: HTTP
    port: 80
    hostname: api.example.com
"""
        res = KubernetesParser().parse_content(content, "gateway.yaml")
        assert len(res.gateways) == 1
        assert res.gateways[0].listeners[0].hostname == "api.example.com"
        assert res.gateways[0].listeners[0].port == 80

    def test_unknown_kinds_are_ignored(self) -> None:
        content = """apiVersion: v1
kind: ConfigMap
metadata: {name: cfg}
other: stuff
"""
        res = KubernetesParser().parse_content(content, "cfg.yaml")
        assert res.workloads == [] and res.services == [] and res.ingresses == []

    def test_no_cross_namespace(self) -> None:
        # Same resource name in two namespaces stays isolated by identity key.
        content = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api, namespace: a}\n"
            "spec: {selector: {matchLabels: {app: api}}, template: {spec: {containers: []}}}\n"
            "---\n"
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: api, namespace: b}\n"
            "spec: {selector: {matchLabels: {app: api}}, template: {spec: {containers: []}}}\n"
        )
        res = KubernetesParser().parse_content(content, "multi.yaml")
        keys = [w.identity.key() for w in res.workloads]
        assert keys == ["kubernetes:a:Deployment:api", "kubernetes:b:Deployment:api"]


# ===========================================================================
# Terraform parsing
# ===========================================================================


class TestTerraformParsing:
    def test_alb_resources_and_attributes(self) -> None:
        res = TerraformParser().parse_directory(FIXTURES / "terraform" / "alb")
        types = {r.resource_type for r in res.tf_resources}
        assert {"aws_lb", "aws_lb_listener", "aws_lb_target_group"} <= types
        lb = next(r for r in res.tf_resources if r.resource_type == "aws_lb")
        assert lb.name == "app"
        assert lb.full_name == "aws_lb.app"
        assert lb.attributes.get("internal") is False
        listener = next(r for r in res.tf_resources if r.resource_type == "aws_lb_listener")
        assert listener.attributes.get("protocol") == "HTTPS"

    def test_references_extracted(self) -> None:
        res = TerraformParser().parse_directory(FIXTURES / "terraform" / "alb")
        listener = next(r for r in res.tf_resources if r.resource_type == "aws_lb_listener")
        assert "aws_lb.app.arn" in listener.references.values()
        assert "aws_lb_target_group.app.arn" in listener.references.values()

    def test_apigateway_and_cloudfront(self) -> None:
        api = TerraformParser().parse_directory(FIXTURES / "terraform" / "api_gateway")
        assert {r.resource_type for r in api.tf_resources} & {"aws_api_gateway", "aws_apigatewayv2_api"}
        cf = TerraformParser().parse_directory(FIXTURES / "terraform" / "cloudfront")
        assert any(r.resource_type == "aws_cloudfront_distribution" for r in cf.tf_resources)

    def test_unsupported_resources_ignored(self) -> None:
        res = TerraformParser().parse_directory(FIXTURES / "terraform" / "negative")
        assert res.tf_resources == []

    def test_hcl_quotes_are_stripped(self) -> None:
        # python-hcl2 keeps "aws_lb" / "HTTPS" quoted; the parser must strip.
        content = (
            'resource "aws_lb" "app" {\n'
            '  internal = false\n'
            '  load_balancer_type = "application"\n'
            "}\n"
        )
        res = TerraformParser().parse_content(content, "main.tf")
        assert len(res.tf_resources) == 1
        assert res.tf_resources[0].resource_type == "aws_lb"
        assert res.tf_resources[0].name == "app"
        assert res.tf_resources[0].attributes["internal"] is False

    def test_tf_json_supported(self) -> None:
        content = (
            '{"resource": {"aws_lb": {"app": {"internal": false, "name": "app-lb"}}}}'
        )
        res = TerraformParser().parse_content(content, "main.tf.json")
        assert len(res.tf_resources) == 1
        assert res.tf_resources[0].resource_type == "aws_lb"
