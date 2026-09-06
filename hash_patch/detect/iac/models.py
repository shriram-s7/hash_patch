"""hash_patch/detect/iac/models.py — IaC Topology Evidence Model.

Deterministic model for deployment topology evidence used to enrich
cryptographic findings with exposure context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IacType(str, Enum):
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"


class K8sResourceKind(str, Enum):
    DEPLOYMENT = "Deployment"
    STATEFUL_SET = "StatefulSet"
    DAEMON_SET = "DaemonSet"
    SERVICE = "Service"
    INGRESS = "Ingress"
    GATEWAY = "Gateway"
    HTTP_ROUTE = "HTTPRoute"
    CONFIG_MAP = "ConfigMap"
    SECRET = "Secret"
    NAMESPACE = "Namespace"


class TfResourceType(str, Enum):
    AWS_LB = "aws_lb"
    AWS_ALB = "aws_alb"
    AWS_LB_LISTENER = "aws_lb_listener"
    AWS_LB_TARGET_GROUP = "aws_lb_target_group"
    AWS_API_GATEWAY = "aws_api_gateway"
    AWS_API_GATEWAY_V2 = "aws_apigatewayv2_api"
    AWS_CLOUDFRONT = "aws_cloudfront_distribution"
    AZURE_LB = "azurerm_lb"
    AZURE_APP_GATEWAY = "azurerm_application_gateway"
    GCP_LB = "google_compute_global_address"
    GCP_URL_MAP = "google_compute_url_map"


class ServiceType(str, Enum):
    CLUSTER_IP = "ClusterIP"
    NODE_PORT = "NodePort"
    LOAD_BALANCER = "LoadBalancer"
    EXTERNAL_NAME = "ExternalName"
    UNKNOWN = "Unknown"


class ExposureState(str, Enum):
    UNKNOWN = "unknown"
    INTERNAL = "internal"
    EXTERNAL = "external"
    MIXED = "mixed"


class CorrelationStrength(str, Enum):
    DIRECT = "direct"
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ResourceIdentity:
    """Deterministic identity for an IaC resource."""
    iac_type: IacType
    namespace: str | None
    kind: str
    name: str

    def __str__(self) -> str:
        parts = []
        if self.namespace:
            parts.append(self.namespace)
        parts.append(f"{self.kind}/{self.name}")
        return "/".join(parts)

    def key(self) -> str:
        """Stable key for indexing."""
        ns = self.namespace or "default"
        return f"{self.iac_type.value}:{ns}:{self.kind}:{self.name}"


@dataclass
class Workload:
    """A deployable workload (Deployment, StatefulSet, DaemonSet)."""
    identity: ResourceIdentity
    selector: dict[str, str] = field(default_factory=dict)
    containers: list[ContainerSpec] = field(default_factory=list)
    namespace: str = "default"
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    @property
    def pod_labels(self) -> dict[str, str]:
        return self.selector


@dataclass
class ContainerSpec:
    """Container specification within a workload."""
    name: str
    image: str
    image_digest: str | None = None
    ports: list[int] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Service:
    """Kubernetes Service."""
    identity: ResourceIdentity
    selector: dict[str, str] = field(default_factory=dict)
    service_type: ServiceType = ServiceType.UNKNOWN
    ports: list[ServicePort] = field(default_factory=list)
    namespace: str = "default"

    def matches_workload(self, workload: Workload) -> bool:
        """Check if this service selects the given workload.

        Namespace is part of resource identity per Phase 4; a Service in one
        namespace can never select a Workload in another, even when labels
        match perfectly (label selectors are namespace-scoped on a real
        cluster and must be here too)."""
        if self.namespace != workload.namespace:
            return False
        if not self.selector or not workload.selector:
            return False
        return all(workload.selector.get(k) == v for k, v in self.selector.items())


@dataclass
class ServicePort:
    port: int
    target_port: int | str | None = None
    node_port: int | None = None
    protocol: str = "TCP"
    name: str | None = None


@dataclass
class Ingress:
    """Kubernetes Ingress."""
    identity: ResourceIdentity
    rules: list[IngressRule] = field(default_factory=list)
    default_backend: IngressBackend | None = None
    namespace: str = "default"
    class_name: str | None = None


@dataclass
class IngressRule:
    host: str | None
    paths: list[IngressPath] = field(default_factory=list)


@dataclass
class IngressPath:
    path: str
    path_type: str
    backend: IngressBackend


@dataclass
class IngressBackend:
    service_name: str
    service_port: int | str


@dataclass
class Gateway:
    """Kubernetes Gateway API Gateway."""
    identity: ResourceIdentity
    listeners: list[GatewayListener] = field(default_factory=list)
    namespace: str = "default"


@dataclass
class GatewayListener:
    name: str
    protocol: str
    port: int
    hostname: str | None = None


@dataclass
class TfResource:
    """Terraform resource."""
    resource_type: str
    name: str
    module: str | None = None
    attributes: dict[str, object] = field(default_factory=dict)
    references: dict[str, str] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        if self.module:
            return f"module.{self.module}.{self.resource_type}.{self.name}"
        return f"{self.resource_type}.{self.name}"


@dataclass
class TopologyEvidence:
    """Evidence linking a crypto finding to deployment topology."""
    workload: Workload | None = None
    service: Service | None = None
    ingress: Ingress | None = None
    gateway: Gateway | None = None
    tf_resources: list[TfResource] = field(default_factory=list)
    exposure_state: ExposureState = ExposureState.UNKNOWN
    correlation_strength: CorrelationStrength = CorrelationStrength.NONE
    evidence_chain: list[str] = field(default_factory=list)

    def to_properties(self) -> dict[str, str]:
        """Convert to CBOM properties.

        Resource identities use the canonical deterministic key()
        (`kubernetes:production:Deployment:payment-api`) — the same string the
        Q&A index and the report use — never the human-readable __str__."""
        props = {
            "hash_patch:exposureState": self.exposure_state.value,
            "hash_patch:correlationStrength": self.correlation_strength.value,
        }
        if self.workload:
            props["hash_patch:workload"] = self.workload.identity.key()
            props["hash_patch:namespace"] = self.workload.namespace
        if self.service:
            props["hash_patch:service"] = self.service.identity.key()
            props["hash_patch:serviceType"] = self.service.service_type.value
        if self.ingress:
            props["hash_patch:ingress"] = self.ingress.identity.key()
            hosts = [r.host for r in self.ingress.rules if r.host]
            if hosts:
                props["hash_patch:ingressHosts"] = ",".join(hosts)
        if self.gateway:
            props["hash_patch:gateway"] = self.gateway.identity.key()
        if self.tf_resources:
            props["hash_patch:tfResources"] = ",".join(r.full_name for r in self.tf_resources)
        if self.evidence_chain:
            props["hash_patch:evidenceChain"] = " -> ".join(self.evidence_chain)
        return props


@dataclass
class IacScanResult:
    """Result of scanning IaC files."""
    workloads: list[Workload] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    ingresses: list[Ingress] = field(default_factory=list)
    gateways: list[Gateway] = field(default_factory=list)
    tf_resources: list[TfResource] = field(default_factory=list)
    namespaces: set[str] = field(default_factory=set)
    parse_errors: list[str] = field(default_factory=list)

    def get_workload_by_identity(self, identity: ResourceIdentity) -> Workload | None:
        for w in self.workloads:
            if w.identity == identity:
                return w
        return None

    def get_service_by_identity(self, identity: ResourceIdentity) -> Service | None:
        for s in self.services:
            if s.identity == identity:
                return s
        return None

    def get_ingress_by_identity(self, identity: ResourceIdentity) -> Ingress | None:
        for i in self.ingresses:
            if i.identity == identity:
                return i
        return None

    def find_services_for_workload(self, workload: Workload) -> list[Service]:
        return [s for s in self.services if s.matches_workload(workload)]

    def find_ingresses_for_service(self, service: Service) -> list[Ingress]:
        result = []
        for ing in self.ingresses:
            if ing.namespace != service.namespace:
                continue
            for rule in ing.rules:
                for path in rule.paths:
                    if path.backend.service_name == service.identity.name:
                        result.append(ing)
                        break
        return result


@dataclass
class EnrichedFinding:
    """A crypto finding enriched with topology evidence."""
    asset_id: str
    algorithm_name: str
    container_image: str | None
    image_digest: str | None
    topology: TopologyEvidence | None = None
    original_reachability: str = "unknown"
