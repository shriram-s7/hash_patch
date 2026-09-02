"""pratyaksha/detect/config/tls_config.py — Static TLS/SSL configuration file detector (Pillar 4).

Parses deployed configuration directives in:
- nginx (ssl_protocols, ssl_ciphers)
- Apache httpd (SSLProtocol, SSLCipherSuite)
- Java .properties / java.security (jdk.tls.*, tls.protocols, tls.ciphers)

Matches configuration values against rules/legacy_tls_config.yaml to determine
if deprecated/weak protocols or ciphers are permitted (allows_legacy=True).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml

from pratyaksha.model.config_finding import TlsConfigFinding
from pratyaksha.model.evidence import Evidence

_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "legacy_tls_config.yaml"


def _load_legacy_rules() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not _RULES_PATH.is_file():
        return [], []
    with _RULES_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("legacy_protocols", []), data.get("legacy_ciphers", [])


# Nginx regex patterns
# ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
_NGINX_PROTOCOLS_RE = re.compile(
    r"^\s*ssl_protocols\s+(?P<value>[^;#]+);?", re.MULTILINE | re.IGNORECASE
)
_NGINX_CIPHERS_RE = re.compile(
    r"^\s*ssl_ciphers\s+(?P<value>[^;#]+);?", re.MULTILINE | re.IGNORECASE
)

# Apache regex patterns
# SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
_APACHE_PROTOCOLS_RE = re.compile(
    r"^\s*SSLProtocol\s+(?P<value>[^#\r\n]+)", re.MULTILINE | re.IGNORECASE
)
_APACHE_CIPHERS_RE = re.compile(
    r"^\s*SSLCipherSuite\s+(?P<value>[^#\r\n]+)", re.MULTILINE | re.IGNORECASE
)

# Java / Properties regex patterns
# tls.protocols=TLSv1,TLSv1.2 or jdk.tls.client.protocols=TLSv1
_JAVA_PROTOCOLS_RE = re.compile(
    r"^\s*(?:jdk\.tls\.(?:client\.|server\.)?protocols|tls\.protocols)\s*=\s*(?P<value>[^#\r\n]+)",
    re.MULTILINE | re.IGNORECASE,
)
_JAVA_CIPHERS_RE = re.compile(
    r"^\s*(?:jdk\.tls\.(?:client\.|server\.)?ciphers|tls\.ciphers)\s*=\s*(?P<value>[^#\r\n]+)",
    re.MULTILINE | re.IGNORECASE,
)


def _check_legacy_protocols(
    raw_value: str,
    rules: list[dict[str, Any]],
    format_hint: str,
) -> tuple[bool, list[str], Literal["high", "medium", "none"]]:
    """Check whether a protocol directive permits any legacy TLS/SSL versions."""
    tokens = [t.strip() for t in re.split(r"[\s,;]+", raw_value) if t.strip()]
    if not tokens:
        return False, [], "none"

    # Apache special case: 'all' enables SSLv3, TLSv1, TLSv1.1, TLSv1.2
    # Subtractions like -TLSv1, -TLSv1.1, -SSLv3 remove them.
    if format_hint == "apache":
        has_all = any(t.lower() == "all" for t in tokens)
        subtractions = {
            t[1:].upper() for t in tokens if t.startswith("-")
        }
        additions = {
            t.lstrip("+").upper() for t in tokens if not t.startswith("-") and t.lower() != "all"
        }

        reasons: list[str] = []
        highest_severity: Literal["high", "medium", "none"] = "none"

        for rule in rules:
            rule_tokens = [tok.upper() for tok in rule.get("tokens", [])]
            # If 'all' is active, check if all rule tokens were subtracted
            rule_active = False
            if has_all and not any(rt in subtractions for rt in rule_tokens):
                rule_active = True
            if any(rt in additions for rt in rule_tokens):
                rule_active = True

            if rule_active:
                reasons.append(f"{rule['name']} ({rule['description']})")
                if rule.get("severity") == "high":
                    highest_severity = "high"
                elif highest_severity != "high" and rule.get("severity") == "medium":
                    highest_severity = "medium"

        return len(reasons) > 0, sorted(reasons), highest_severity

    # General token matching (Nginx, Java properties, standard token list)
    reasons = []
    highest_sev: Literal["high", "medium", "none"] = "none"
    tokens_upper = {t.upper() for t in tokens}

    for rule in rules:
        rule_tokens = [tok.upper() for tok in rule.get("tokens", [])]
        if any(rt in tokens_upper for rt in rule_tokens):
            reasons.append(f"{rule['name']} ({rule['description']})")
            if rule.get("severity") == "high":
                highest_sev = "high"
            elif highest_sev != "high" and rule.get("severity") == "medium":
                highest_sev = "medium"

    return len(reasons) > 0, sorted(reasons), highest_sev


def _check_legacy_ciphers(
    raw_value: str,
    rules: list[dict[str, Any]],
) -> tuple[bool, list[str], Literal["high", "medium", "none"]]:
    """Check whether a cipher suite string permits any weak ciphers."""
    # Split by colon, comma, or whitespace
    tokens = [t.strip() for t in re.split(r"[:\s,;]+", raw_value) if t.strip()]
    reasons = []
    highest_sev: Literal["high", "medium", "none"] = "none"

    # Filter out negated ciphers like !aNULL, !MD5, !RC4
    active_tokens = [t for t in tokens if not t.startswith("!")]

    for rule in rules:
        patterns = rule.get("patterns", [])
        matched = False
        for token in active_tokens:
            token_upper = token.upper()
            if any(p.upper() in token_upper for p in patterns):
                matched = True
                break
        if matched:
            reasons.append(f"{rule['name']} ({rule['description']})")
            if rule.get("severity") == "high":
                highest_sev = "high"
            elif highest_sev != "high" and rule.get("severity") == "medium":
                highest_sev = "medium"

    return len(reasons) > 0, sorted(reasons), highest_sev


def _make_evidence(content: str, match: re.Match[str], file_path: Path) -> Evidence:
    start = match.start()
    line = content[:start].count("\n") + 1
    last_nl = content[:start].rfind("\n")
    col = start - last_nl if last_nl != -1 else start + 1
    snippet = match.group(0).strip()
    return Evidence(
        locator=str(file_path),
        line=line,
        column=col,
        byte_offset=len(content[:start].encode("utf-8")),
        snippet=snippet,
        source_type="config",
        detector_id="tls-config",
        detector_version="0.1.0",
    )


def detect_tls_config_file(file_path: Path) -> list[TlsConfigFinding]:
    """Parse a configuration file and extract any recognized TLS protocol or
    cipher directives.

    Silently returns [] if the file format or directives are unrecognized.
    """
    if not file_path.is_file():
        return []

    # Filter by common config extensions or file names
    name_lower = file_path.name.lower()
    suffix_lower = file_path.suffix.lower()

    is_nginx = "nginx" in name_lower or suffix_lower == ".conf"
    is_apache = "httpd" in name_lower or "apache" in name_lower or suffix_lower == ".conf"
    is_properties = suffix_lower in (".properties", ".security", ".cfg", ".ini") or "security" in name_lower

    if not (is_nginx or is_apache or is_properties or suffix_lower == ".conf"):
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    legacy_protocols, legacy_ciphers = _load_legacy_rules()
    findings: list[TlsConfigFinding] = []

    # 1. Nginx checks
    for m in _NGINX_PROTOCOLS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_protocols(val, legacy_protocols, "nginx")
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="protocol_version",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="nginx",
            )
        )

    for m in _NGINX_CIPHERS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_ciphers(val, legacy_ciphers)
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="cipher_suite",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="nginx",
            )
        )

    # 2. Apache checks
    for m in _APACHE_PROTOCOLS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_protocols(val, legacy_protocols, "apache")
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="protocol_version",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="apache",
            )
        )

    for m in _APACHE_CIPHERS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_ciphers(val, legacy_ciphers)
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="cipher_suite",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="apache",
            )
        )

    # 3. Java properties checks
    for m in _JAVA_PROTOCOLS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_protocols(val, legacy_protocols, "java-properties")
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="protocol_version",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="java-properties",
            )
        )

    for m in _JAVA_CIPHERS_RE.finditer(content):
        val = m.group("value").strip()
        allows_legacy, reasons, sev = _check_legacy_ciphers(val, legacy_ciphers)
        ev = _make_evidence(content, m, file_path)
        findings.append(
            TlsConfigFinding(
                kind="cipher_suite",
                value=val,
                allows_legacy=allows_legacy,
                legacy_reasons=reasons,
                severity=sev,
                evidence=[ev],
                source_file=str(file_path),
                config_format="java-properties",
            )
        )

    return findings
