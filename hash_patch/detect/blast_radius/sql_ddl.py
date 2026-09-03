"""hash_patch/detect/blast_radius/sql_ddl.py — SQL DDL fixed-width-column
detector for Pillar 3 (Blast Radius).

Parses `CREATE TABLE (...)` statements with a **regex-based** lightweight
parser, not a full SQL grammar — there is no tree-sitter-sql dependency in
this project, and CREATE TABLE column lists are regular enough that a
targeted regex over each table's column-list text is sufficient and easy to
audit. This is NOT a general SQL parser: it only recognises
`CREATE TABLE ... ( <column-defs> )` blocks and, within their column-list
text, `<column_name> <TYPE>(<N>)` column definitions for VARCHAR/CHAR/
BINARY/VARBINARY/BLOB. Anything else (constraints, computed columns, views,
ALTER TABLE, a DEFAULT expression containing parentheses, etc.) is simply
not matched — never mis-parsed into a guessed size. A false negative here is
far safer than inventing one.

Byte-size assumption (explicit, see docs/BLAST_RADIUS.md):
  - VARCHAR(N) / CHAR(N)              -> N bytes. We assume 1 byte per
    character (ASCII-range content), since the crypto material these
    columns are named for — hex- or base64-encoded keys/signatures/
    digests — is ASCII-range by construction. A multi-byte charset storing
    raw binary in a text column would be unusual practice and is out of
    scope.
  - BINARY(N) / VARBINARY(N) / BLOB(N) -> N bytes directly (already a byte
    count; no charset assumption needed).
  - BLOB / TEXT with NO explicit size -> unresolved, no SizeConstraint
    emitted (never guessed).

Crypto-name matching reuses rules/blast_radius_names.yaml via
hash_patch.detect.blast_radius.names — the exact same pattern list
hash_patch/detect/blast_radius/c_buffers.py uses, never duplicated.
"""

from __future__ import annotations

import re
from pathlib import Path

from hash_patch.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from hash_patch.model.blast_radius import SizeConstraint
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "sql-blast-radius-ddl"
_DETECTOR_VERSION = "0.1.0"

_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(?P<table>\w+)[`\"\]]?\s*\((?P<body>.*?)\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_COLUMN_RE = re.compile(
    r"(?P<name>\w+)\s+(?P<type>VARCHAR|CHAR|BINARY|VARBINARY|BLOB)\s*\(\s*(?P<size>\d+)\s*\)",
    re.IGNORECASE,
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class SqlDdlBlastRadiusDetector:
    """Detects fixed-width SQL columns named like crypto material. Emits
    SizeConstraint, never CryptoAsset — see
    hash_patch/detect/blast_radius/__init__.py.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        self._patterns: list[NamePattern] = load_name_patterns()

    def supports(self, target: Path) -> bool:
        return target.is_file() and target.suffix.lower() == ".sql"

    def detect(self, target: Path) -> list[SizeConstraint]:
        if not self.supports(target):
            return []

        text = target.read_text(encoding="utf-8", errors="replace")
        locator = str(target)
        results: list[SizeConstraint] = []

        for table_match in _CREATE_TABLE_RE.finditer(text):
            body = table_match.group("body")
            body_offset = table_match.start("body")

            for col_match in _COLUMN_RE.finditer(body):
                name = col_match.group("name")
                if match_name_pattern(name, self._patterns) is None:
                    continue

                # Same-byte-count assumption for both families — see the
                # module docstring for the ASCII-range rationale on the
                # char-type branch.
                declared_bytes = int(col_match.group("size"))

                abs_offset = body_offset + col_match.start()
                evidence = Evidence(
                    source_type="source",
                    locator=locator,
                    line=_line_of(text, abs_offset),
                    column=None,
                    byte_offset=abs_offset,
                    snippet=col_match.group(0),
                    detector_id=_DETECTOR_ID,
                    detector_version=_DETECTOR_VERSION,
                )
                results.append(
                    SizeConstraint(
                        kind="db_column",
                        name=name,
                        declared_bytes=declared_bytes,
                        evidence=[evidence],
                        language="sql",
                    )
                )

        return results
