"""pratyaksha/detect/config/source_tls_intent.py — Detect explicit TLS protocol/cipher
intent in Python and Java source code (Pillar 4).

Finds statements such as:
- Python: `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3` or `ssl.PROTOCOL_TLSv1_2`
- Java: `SSLContext.getInstance("TLSv1.3")`

Rules live in rules/tls_source_intent.yaml (no hardcoded API names in Python).
Emits TlsConfigFinding with config_format="source-code-intent".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

try:
    import tree_sitter_python as _tspy
    from tree_sitter import Language as _Language
    from tree_sitter import Parser as _Parser

    _PY_LANG = _Language(_tspy.language())
    _PY_PARSER = _Parser(_PY_LANG)
    _PY_AVAILABLE = True
except Exception:  # noqa: BLE001
    _PY_AVAILABLE = False
    _PY_PARSER = None  # type: ignore[assignment]

try:
    import tree_sitter_java as _tsjava
    from tree_sitter import Language as _Language
    from tree_sitter import Parser as _Parser

    _JAVA_LANG = _Language(_tsjava.language())
    _JAVA_PARSER = _Parser(_JAVA_LANG)
    _JAVA_AVAILABLE = True
except Exception:  # noqa: BLE001
    _JAVA_AVAILABLE = False
    _JAVA_PARSER = None  # type: ignore[assignment]

from pratyaksha.model.config_finding import TlsConfigFinding
from pratyaksha.model.evidence import Evidence

_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "tls_source_intent.yaml"


def _load_source_intent_rules() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not _RULES_PATH.is_file():
        return [], []
    with _RULES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("python", []), data.get("java", [])


def _detect_python_intent(file_path: Path, rules: list[dict[str, Any]]) -> list[TlsConfigFinding]:
    if not _PY_AVAILABLE or _PY_PARSER is None:
        return []

    try:
        source_bytes = file_path.read_bytes()
    except OSError:
        return []

    tree = _PY_PARSER.parse(source_bytes)
    lines = source_bytes.splitlines()
    findings: list[TlsConfigFinding] = []
    seen_keys: set[tuple[int, str]] = set()

    def visit(node: Any) -> None:
        if node.type in ("attribute", "identifier", "dotted_name", "string"):
            node_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip("\"'")
            for rule in rules:
                patterns = rule.get("patterns", [])
                if any(p == node_text or node_text.endswith(p) for p in patterns):
                    line = node.start_point[0] + 1
                    col = node.start_point[1] + 1
                    key = (line, rule["protocol"])
                    if key not in seen_keys:
                        seen_keys.add(key)
                        snippet = (
                            lines[node.start_point[0]].decode("utf-8", errors="replace").strip()
                            if node.start_point[0] < len(lines)
                            else node_text
                        )
                        ev = Evidence(
                            source_type="source",
                            locator=str(file_path),
                            line=line,
                            column=col,
                            byte_offset=node.start_byte,
                            snippet=snippet,
                            detector_id="source-tls-intent",
                            detector_version="0.1.0",
                        )
                        allows_legacy = rule.get("allows_legacy", False)
                        reasons = [rule["protocol"]] if allows_legacy else []
                        sev = "none"
                        if allows_legacy:
                            sev = "high" if rule["protocol"] in ("SSLv2", "SSLv3") else "medium"

                        findings.append(
                            TlsConfigFinding(
                                kind="protocol_version",
                                value=rule["protocol"],
                                allows_legacy=allows_legacy,
                                legacy_reasons=reasons,
                                severity=sev,  # type: ignore[arg-type]
                                evidence=[ev],
                                source_file=str(file_path),
                                config_format="source-code-intent",
                            )
                        )
                    break
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return findings


def _detect_java_intent(file_path: Path, rules: list[dict[str, Any]]) -> list[TlsConfigFinding]:
    if not _JAVA_AVAILABLE or _JAVA_PARSER is None:
        return []

    try:
        source_bytes = file_path.read_bytes()
    except OSError:
        return []

    tree = _JAVA_PARSER.parse(source_bytes)
    lines = source_bytes.splitlines()
    findings: list[TlsConfigFinding] = []
    seen_keys: set[tuple[int, str]] = set()

    def visit(node: Any) -> None:
        if node.type in ("string_literal", "identifier"):
            node_text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip("\"'")
            for rule in rules:
                patterns = rule.get("patterns", [])
                if node_text in patterns:
                    line = node.start_point[0] + 1
                    col = node.start_point[1] + 1
                    key = (line, rule["protocol"])
                    if key not in seen_keys:
                        seen_keys.add(key)
                        snippet = (
                            lines[node.start_point[0]].decode("utf-8", errors="replace").strip()
                            if node.start_point[0] < len(lines)
                            else node_text
                        )
                        ev = Evidence(
                            source_type="source",
                            locator=str(file_path),
                            line=line,
                            column=col,
                            byte_offset=node.start_byte,
                            snippet=snippet,
                            detector_id="source-tls-intent",
                            detector_version="0.1.0",
                        )
                        allows_legacy = rule.get("allows_legacy", False)
                        reasons = [rule["protocol"]] if allows_legacy else []
                        sev = "none"
                        if allows_legacy:
                            sev = "high" if rule["protocol"] in ("SSLv2", "SSLv3") else "medium"

                        findings.append(
                            TlsConfigFinding(
                                kind="protocol_version",
                                value=rule["protocol"],
                                allows_legacy=allows_legacy,
                                legacy_reasons=reasons,
                                severity=sev,  # type: ignore[arg-type]
                                evidence=[ev],
                                source_file=str(file_path),
                                config_format="source-code-intent",
                            )
                        )
                    break
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return findings


def detect_source_tls_intent(file_path: Path) -> list[TlsConfigFinding]:
    """Inspect Python or Java source file for explicit TLS protocol version or cipher
    intent declarations.
    """
    if not file_path.is_file():
        return []

    suffix = file_path.suffix.lower()
    py_rules, java_rules = _load_source_intent_rules()

    if suffix == ".py":
        return _detect_python_intent(file_path, py_rules)
    elif suffix == ".java":
        return _detect_java_intent(file_path, java_rules)

    return []
