"""hash_patch/detect/iac/terraform.py — Terraform Parser.

Static parser for Terraform HCL/JSON relevant to exposure/topology analysis.
Does NOT execute terraform plan/apply or contact cloud APIs.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import hcl2

from hash_patch.detect.iac.models import (
    IacScanResult,
    TfResource,
)

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 10 * 1024 * 1024
_MAX_RESOURCES = 1000

SUPPORTED_RESOURCE_TYPES = {
    "aws_lb",
    "aws_alb",
    "aws_lb_listener",
    "aws_lb_target_group",
    "aws_api_gateway",
    "aws_apigatewayv2_api",
    "aws_cloudfront_distribution",
    "azurerm_lb",
    "azurerm_application_gateway",
    "google_compute_global_address",
    "google_compute_url_map",
    "google_compute_target_https_proxy",
    "google_compute_forwarding_rule",
}


class TerraformParser:
    """Parse Terraform files for topology evidence."""

    def __init__(self) -> None:
        self.result = IacScanResult()
        self._resource_counter = 0

    def parse_file(self, file_path: Path) -> IacScanResult:
        """Parse a single Terraform file (.tf or .tf.json)."""
        size_error = self._validate_file(file_path)
        content = file_path.read_text(encoding="utf-8", errors="replace")
        if size_error:
            self.result.parse_errors.append(size_error)
            return self.result
        return self.parse_content(content, source_file=str(file_path))

    def parse_directory(self, dir_path: Path) -> IacScanResult:
        """Parse all Terraform files in a directory."""
        self.result = IacScanResult()
        for tf_file in sorted(dir_path.rglob("*.tf")):
            self.parse_file(tf_file)
        for tf_json in sorted(dir_path.rglob("*.tf.json")):
            self.parse_file(tf_json)
        return self.result

    def parse_content(self, content: str, source_file: str = "<string>") -> IacScanResult:
        """Parse Terraform HCL or JSON content."""
        try:
            if source_file.endswith(".json") or content.strip().startswith("{"):
                parsed = json.loads(content)
            else:
                parsed = hcl2.loads(content)
        except (json.JSONDecodeError, Exception) as e:
            self.result.parse_errors.append(f"{source_file}: Parse error: {e}")
            return self.result

        if isinstance(parsed, list):
            for doc in parsed:
                self._parse_document(doc, source_file)
        elif isinstance(parsed, dict):
            self._parse_document(parsed, source_file)

        return self.result

    def _validate_file(self, file_path: Path) -> str | None:
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

        for block_type, blocks in doc.items():
            if block_type == "resource":
                # HCL (`hcl2`) returns a list of single-resource blocks, while
                # tf.json has one top-level dict mapping type -> instances.
                resource_blocks = blocks if isinstance(blocks, list) else [blocks]
                self._parse_resources(resource_blocks, source)
            elif block_type == "module":
                module_blocks = blocks if isinstance(blocks, list) else [blocks]
                self._parse_modules(module_blocks, source)

    def _parse_resources(self, resources: list[dict[str, Any]], source: str) -> None:
        for resource_block in resources:
            if not isinstance(resource_block, dict):
                continue
            for resource_type, instances in resource_block.items():
                resource_type = self._strip_hcl_quotes(str(resource_type))
                if resource_type not in SUPPORTED_RESOURCE_TYPES:
                    continue
                if not isinstance(instances, dict):
                    continue
                for name, config in instances.items():
                    if not isinstance(config, dict):
                        continue
                    name = self._strip_hcl_quotes(str(name))
                    self._resource_counter += 1
                    if self._resource_counter > _MAX_RESOURCES:
                        return

                    module = self._extract_module(source)
                    attributes = self._extract_attributes(config)
                    references = self._extract_references(config)

                    tf_resource = TfResource(
                        resource_type=resource_type,
                        name=name,
                        module=module,
                        attributes=attributes,
                        references=references,
                    )
                    self.result.tf_resources.append(tf_resource)

    def _parse_modules(self, modules: list[dict[str, Any]], source: str) -> None:
        for module_block in modules:
            if not isinstance(module_block, dict):
                continue
            for module_name, config in module_block.items():
                if not isinstance(config, dict):
                    continue
                source_path = config.get("source")
                if source_path:
                    pass

    def _extract_module(self, source: str) -> str | None:
        match = re.search(r"modules?[/\\]([^/\\]+)", source)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _strip_hcl_quotes(value: str) -> str:
        """python-hcl2 keeps HCL string keys/values wrapped in double quotes
        (e.g. "aws_lb", "HTTPS"); strip them so lookups match the YAML rule
        tables and supported-resource set without weakening determinism."""
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        return value

    def _extract_attributes(self, config: dict[str, Any]) -> dict[str, object]:
        attrs: dict[str, object] = {}
        for key, value in config.items():
            if key.startswith("_"):
                continue
            if isinstance(value, str):
                attrs[key] = self._strip_hcl_quotes(value)
            elif isinstance(value, (int, float, bool, list, dict)):
                attrs[key] = value
            elif value is None:
                attrs[key] = None
        return attrs

    def _extract_references(self, config: dict[str, Any]) -> dict[str, str]:
        refs: dict[str, str] = {}
        ref_pattern = re.compile(r"\$\{([^}]+)\}")

        def find_refs(obj: Any, path: str = "") -> None:
            if isinstance(obj, str):
                for match in ref_pattern.finditer(obj):
                    refs[path or "value"] = self._strip_hcl_quotes(match.group(1))
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    find_refs(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    find_refs(v, f"{path}[{i}]")

        find_refs(config)
        return refs


def parse_terraform_file(file_path: Path) -> IacScanResult:
    """Convenience function to parse a single Terraform file."""
    parser = TerraformParser()
    return parser.parse_file(file_path)


def parse_terraform_directory(dir_path: Path) -> IacScanResult:
    """Convenience function to parse all Terraform files in a directory."""
    parser = TerraformParser()
    return parser.parse_directory(dir_path)
