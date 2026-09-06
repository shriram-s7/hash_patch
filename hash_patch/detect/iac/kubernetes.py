"""hash_patch/detect/iac/kubernetes.py — Kubernetes YAML Parser.

Static parser for Kubernetes manifests relevant to exposure/topology analysis.
Does NOT execute kubectl or contact cluster APIs.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from hash_patch.detect.iac.models import (
    ContainerSpec,
    Gateway,
    GatewayListener,
    IacScanResult,
    IacType,
    Ingress,
    IngressBackend,
    IngressPath,
    IngressRule,
    K8sResourceKind,
    ResourceIdentity,
    Service,
    ServicePort,
    ServiceType,
    Workload,
)

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 50 * 1024 * 1024
_MAX_DOCUMENTS = 500
_MAX_NESTING_DEPTH = 50
_MAX_STRING_LENGTH = 10000


class KubernetesParser:
    """Parse Kubernetes YAML manifests for topology evidence."""

    def __init__(self) -> None:
        self.result = IacScanResult()

    def parse_file(self, file_path: Path) -> IacScanResult:
        """Parse a single Kubernetes YAML file."""
        size_error = self._validate_file(file_path)
        content = file_path.read_text(encoding="utf-8", errors="replace")
        if size_error:
            self.result = IacScanResult()
            self.result.parse_errors.append(size_error)
            return self.result
        return self.parse_content(content, source_file=str(file_path))

    def parse_content(self, content: str, source_file: str = "<string>") -> IacScanResult:
        """Parse Kubernetes YAML content (supports multi-document)."""
        self.result = IacScanResult()
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            self.result.parse_errors.append(f"{source_file}: YAML parse error: {e}")
            return self.result

        if len(docs) > _MAX_DOCUMENTS:
            self.result.parse_errors.append(f"{source_file}: Too many documents ({len(docs)} > {_MAX_DOCUMENTS})")
            docs = docs[:_MAX_DOCUMENTS]

        for i, doc in enumerate(docs):
            if doc is None:
                continue
            self._parse_document(doc, f"{source_file}#doc{i}")

        return self.result

    def _validate_file(self, file_path: Path) -> str | None:
        """Return an error message when the file exceeds size limits else None.

        Oversized inputs must surface as a recorded parse error (scan keeps
        going), never as a raised exception that aborts the scan."""
        try:
            size = file_path.stat().st_size
            if size > _MAX_FILE_SIZE:
                return f"File too large: {size} bytes > {_MAX_FILE_SIZE}"
        except OSError:
            pass
        return None

    def _parse_document(self, doc: dict[str, Any], source: str) -> None:
        if not isinstance(doc, dict):
            return

        kind = doc.get("kind")
        if not kind:
            return

        metadata = doc.get("metadata", {})
        namespace = metadata.get("namespace", "default")
        name = metadata.get("name", "unknown")

        identity = ResourceIdentity(
            iac_type=IacType.KUBERNETES,
            namespace=namespace,
            kind=kind,
            name=name,
        )

        self.result.namespaces.add(namespace)

        try:
            if kind == K8sResourceKind.DEPLOYMENT.value:
                self._parse_deployment(doc, identity, namespace, source)
            elif kind == K8sResourceKind.STATEFUL_SET.value:
                self._parse_stateful_set(doc, identity, namespace, source)
            elif kind == K8sResourceKind.DAEMON_SET.value:
                self._parse_daemon_set(doc, identity, namespace, source)
            elif kind == K8sResourceKind.SERVICE.value:
                self._parse_service(doc, identity, namespace, source)
            elif kind == K8sResourceKind.INGRESS.value:
                self._parse_ingress(doc, identity, namespace, source)
            elif kind == K8sResourceKind.GATEWAY.value:
                self._parse_gateway(doc, identity, namespace, source)
            elif kind == K8sResourceKind.HTTP_ROUTE.value:
                self._parse_http_route(doc, identity, namespace, source)
        except Exception as e:
            self.result.parse_errors.append(f"{source}: Failed to parse {kind}/{name}: {e}")

    def _extract_labels(self, doc: dict[str, Any], path: str = "metadata") -> dict[str, str]:
        metadata = doc.get(path, {})
        return metadata.get("labels", {}) or {}

    def _extract_annotations(self, doc: dict[str, Any], path: str = "metadata") -> dict[str, str]:
        metadata = doc.get(path, {})
        return metadata.get("annotations", {}) or {}

    def _parse_deployment(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        selector = spec.get("selector", {}).get("matchLabels", {}) or {}
        template = spec.get("template", {})
        pod_labels = self._extract_labels(template)
        pod_annotations = self._extract_annotations(template)
        containers = self._parse_containers(template.get("spec", {}).get("containers", []), source)

        workload = Workload(
            identity=identity,
            selector=selector,
            containers=containers,
            namespace=namespace,
            labels=pod_labels,
            annotations=pod_annotations,
        )
        self.result.workloads.append(workload)

    def _parse_stateful_set(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        selector = spec.get("selector", {}).get("matchLabels", {}) or {}
        template = spec.get("template", {})
        pod_labels = self._extract_labels(template)
        pod_annotations = self._extract_annotations(template)
        containers = self._parse_containers(template.get("spec", {}).get("containers", []), source)

        workload = Workload(
            identity=identity,
            selector=selector,
            containers=containers,
            namespace=namespace,
            labels=pod_labels,
            annotations=pod_annotations,
        )
        self.result.workloads.append(workload)

    def _parse_daemon_set(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        selector = spec.get("selector", {}).get("matchLabels", {}) or {}
        template = spec.get("template", {})
        pod_labels = self._extract_labels(template)
        pod_annotations = self._extract_annotations(template)
        containers = self._parse_containers(template.get("spec", {}).get("containers", []), source)

        workload = Workload(
            identity=identity,
            selector=selector,
            containers=containers,
            namespace=namespace,
            labels=pod_labels,
            annotations=pod_annotations,
        )
        self.result.workloads.append(workload)

    def _parse_containers(self, containers: list[dict[str, Any]], source: str) -> list[ContainerSpec]:
        result: list[ContainerSpec] = []
        for c in containers:
            if not isinstance(c, dict):
                continue
            name = c.get("name", "unknown")
            image = c.get("image", "")
            image_digest = None
            if "@" in image:
                _, image_digest = image.split("@", 1)

            ports: list[int] = []
            for p in c.get("ports", []) or []:
                if isinstance(p, dict) and "containerPort" in p:
                    try:
                        ports.append(int(p["containerPort"]))
                    except (ValueError, TypeError):
                        pass

            env: dict[str, str] = {}
            for e in c.get("env", []) or []:
                if isinstance(e, dict) and "name" in e and "value" in e:
                    env[e["name"]] = str(e["value"])

            result.append(ContainerSpec(
                name=name,
                image=image,
                image_digest=image_digest,
                ports=ports,
                env=env,
            ))
        return result

    def _parse_service(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        selector = spec.get("selector", {}) or {}
        svc_type_str = spec.get("type", "ClusterIP")
        try:
            svc_type = ServiceType(svc_type_str)
        except ValueError:
            svc_type = ServiceType.UNKNOWN

        ports: list[ServicePort] = []
        for p in spec.get("ports", []) or []:
            if not isinstance(p, dict):
                continue
            try:
                port = int(p.get("port", 0))
                target_port = p.get("targetPort")
                if isinstance(target_port, str) and target_port.isdigit():
                    target_port = int(target_port)
                node_port = p.get("nodePort")
                if isinstance(node_port, str) and node_port.isdigit():
                    node_port = int(node_port)
                protocol = p.get("protocol", "TCP")
                name = p.get("name")
                ports.append(ServicePort(
                    port=port,
                    target_port=target_port,
                    node_port=node_port,
                    protocol=protocol,
                    name=name,
                ))
            except (ValueError, TypeError):
                pass

        service = Service(
            identity=identity,
            selector=selector,
            service_type=svc_type,
            ports=ports,
            namespace=namespace,
        )
        self.result.services.append(service)

    def _parse_ingress(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        rules: list[IngressRule] = []

        for rule in spec.get("rules", []) or []:
            if not isinstance(rule, dict):
                continue
            host = rule.get("host")
            http = rule.get("http", {})
            paths: list[IngressPath] = []
            for path_spec in http.get("paths", []) or []:
                if not isinstance(path_spec, dict):
                    continue
                path = path_spec.get("path", "/")
                path_type = path_spec.get("pathType", "Prefix")
                backend = path_spec.get("backend", {})
                service = backend.get("service", {})
                service_name = service.get("name", "")
                service_port = service.get("port", {})
                port_number = service_port.get("number")
                port_name = service_port.get("name")
                port = port_number if port_number is not None else port_name

                paths.append(IngressPath(
                    path=path,
                    path_type=path_type,
                    backend=IngressBackend(
                        service_name=service_name,
                        service_port=port if port is not None else 80,
                    ),
                ))
            rules.append(IngressRule(host=host, paths=paths))

        default_backend = None
        if "defaultBackend" in spec:
            backend = spec["defaultBackend"]
            service = backend.get("service", {})
            service_name = service.get("name", "")
            service_port = service.get("port", {})
            port_number = service_port.get("number")
            port_name = service_port.get("name")
            port = port_number if port_number is not None else port_name
            default_backend = IngressBackend(
                service_name=service_name,
                service_port=port if port is not None else 80,
            )

        class_name = spec.get("ingressClassName")

        ingress = Ingress(
            identity=identity,
            rules=rules,
            default_backend=default_backend,
            namespace=namespace,
            class_name=class_name,
        )
        self.result.ingresses.append(ingress)

    def _parse_gateway(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        spec = doc.get("spec", {})
        listeners: list[GatewayListener] = []

        for listener in spec.get("listeners", []) or []:
            if not isinstance(listener, dict):
                continue
            name = listener.get("name", "")
            protocol = listener.get("protocol", "HTTP")
            port = listener.get("port", 80)
            hostname = listener.get("hostname")
            listeners.append(GatewayListener(
                name=name,
                protocol=protocol,
                port=int(port) if isinstance(port, (int, str)) and str(port).isdigit() else 80,
                hostname=hostname,
            ))

        gateway = Gateway(
            identity=identity,
            listeners=listeners,
            namespace=namespace,
        )
        self.result.gateways.append(gateway)

    def _parse_http_route(self, doc: dict[str, Any], identity: ResourceIdentity, namespace: str, source: str) -> None:
        pass


def parse_kubernetes_file(file_path: Path) -> IacScanResult:
    """Convenience function to parse a single Kubernetes YAML file."""
    parser = KubernetesParser()
    return parser.parse_file(file_path)


def parse_kubernetes_content(content: str, source_file: str = "<string>") -> IacScanResult:
    """Convenience function to parse Kubernetes YAML content."""
    parser = KubernetesParser()
    return parser.parse_content(content, source_file)
