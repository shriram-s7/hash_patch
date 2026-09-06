"""hash_patch/detect/blast_radius/python_buffers.py — Python fixed-size
buffer detector for Pillar 3 (Blast Radius).

Detects `bytearray(N)` / `bytes(N)` constructor calls with a fixed integer
size, assigned to a variable, that hold cryptographic material — the Python
equivalent of `unsigned char buf[N]` (C), `[N]byte` (Go), or `new byte[N]`
(Java). Emits SizeConstraint objects for hash_patch/analyze/blast_radius.py
to correlate, exactly like the other three language detectors.

Mirrors hash_patch/detect/blast_radius/java_buffers.py's correlation shape
(same three-pass structure, same shared helpers) rather than relying on
variable-name pattern matching alone — Python's dynamic typing means there
is no static array *type* to key off, so a genuine crypto-material buffer
must be distinguished from an unrelated `bytearray(N)`/`bytes(N)` call by:

  1. NAME pattern match (rules/blast_radius_names.yaml, via
     hash_patch.detect.blast_radius.names) — e.g. `wire_signature`,
     `sig_buf`.
  2. STRUCTURAL size-to-algorithm-output correlation (reusing
     hash_patch.detect.blast_radius.output_sizes — the exact same lookup
     hash_patch/detect/blast_radius/{go,java}_buffers.py already use, never
     a second hand-copied size table) when a crypto API call
     (cryptography.hazmat primitives, pyca signature/cipher objects) is
     present in the SAME enclosing function.
  3. DATA-FLOW correlation: the buffer is later slice-assigned from another
     name (`buf[:len(x)] = x`, `buf[0:N] = x`) inside the same enclosing
     function — the same "did a crypto result get copied into this buffer"
     signal Java's `_is_crypto_data_flow` (System.arraycopy) captures for
     Java's `new byte[N]` + arraycopy idiom.

Only `bytearray(N)` / `bytes(N)` with a LITERAL integer argument are ever
considered — a variable, a `len(...)` expression, or any other non-literal
argument is left unresolved, and no SizeConstraint is emitted for it, never
a guess (matches hash_patch/detect/blast_radius/c_buffers.py's own literal-
or-one-level-#define-only resolution rule).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hash_patch.detect.blast_radius.names import NamePattern, load_name_patterns, match_name_pattern
from hash_patch.detect.blast_radius.output_sizes import infer_field_from_size
from hash_patch.detect.python import _PARSER as _PY_PARSER
from hash_patch.detect.python import _TREE_SITTER_AVAILABLE as _PY_TREE_SITTER_AVAILABLE
from hash_patch.model.blast_radius import SizeConstraint
from hash_patch.model.evidence import Evidence

_DETECTOR_ID = "python-blast-radius-buffers"
_DETECTOR_VERSION = "0.1.0"
_SUPPORTED_EXTENSIONS = frozenset({".py"})
_BUFFER_CONSTRUCTORS = frozenset({"bytearray", "bytes"})

# Common pyca/cryptography (and PyCryptodome) crypto-operation call shapes —
# the Python equivalent of java_buffers.py's _CRYPTO_CALL_RE/_CRYPTO_METHOD_RE.
_CRYPTO_CALL_RE = re.compile(
    r"\b(Ed25519PrivateKey|Ed25519PublicKey|Cipher|Signature|HMAC|Hash|"
    r"rsa|ec|ed25519|dsa|dh)\b"
)
_CRYPTO_METHOD_RE = re.compile(r"\.(sign|verify|encrypt|decrypt|update|finalize|digest)\s*\(")


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


class PythonBufferBlastRadiusDetector:
    """Detects fixed-size `bytearray(N)`/`bytes(N)` allocations in Python
    source files that hold cryptographic material.
    """

    detector_id: str = _DETECTOR_ID
    detector_version: str = _DETECTOR_VERSION

    def __init__(self) -> None:
        self._patterns: list[NamePattern] = load_name_patterns()

    def supports(self, target: Path) -> bool:
        return (
            _PY_TREE_SITTER_AVAILABLE
            and target.is_file()
            and target.suffix.lower() in _SUPPORTED_EXTENSIONS
        )

    def detect(self, target: Path) -> list[SizeConstraint]:
        if not self.supports(target):
            return []
        try:
            source_bytes = target.read_bytes()
        except OSError:
            return []

        tree = _PY_PARSER.parse(source_bytes)  # type: ignore[union-attr]
        locator = str(target)
        return self._walk(tree.root_node, locator)

    def _walk(self, node: Any, locator: str) -> list[SizeConstraint]:
        constraints: list[SizeConstraint] = []
        stack: list[tuple[Any, int]] = [(node, 0)]
        while stack:
            n, depth = stack.pop()
            if depth > 500:
                continue
            if n.type == "assignment":
                c = self._inspect_assignment(n, locator)
                if c is not None:
                    constraints.append(c)
            children = n.children
            if children:
                stack.extend((child, depth + 1) for child in reversed(children))
        return constraints

    def _inspect_assignment(self, node: Any, locator: str) -> SizeConstraint | None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier":
            return None
        if right.type != "call":
            return None

        fn_node = right.child_by_field_name("function")
        if fn_node is None or fn_node.type != "identifier":
            return None
        fn_text = _text(fn_node)
        if fn_text not in _BUFFER_CONSTRUCTORS:
            return None

        args_node = right.child_by_field_name("arguments")
        if args_node is None:
            return None
        int_args = [c for c in args_node.named_children if c.type == "integer"]
        if len(int_args) != 1:
            return None
        try:
            declared_bytes = int(_text(int_args[0]))
        except ValueError:
            return None
        if declared_bytes <= 0:
            return None

        var_name = _text(left)
        return self._correlate_buffer(var_name, declared_bytes, left, node, locator)

    def _correlate_buffer(
        self,
        name: str,
        declared_bytes: int,
        ident_node: Any,
        span_node: Any,
        locator: str,
    ) -> SizeConstraint | None:
        enclosing_scope = self._find_enclosing_function(span_node)
        scope_text = _text(enclosing_scope) if enclosing_scope is not None else ""

        pattern_match = match_name_pattern(name, self._patterns)
        inferred_field: str | None = pattern_match[1] if pattern_match else None

        has_crypto_api = bool(_CRYPTO_CALL_RE.search(scope_text) or _CRYPTO_METHOD_RE.search(scope_text))

        # 1. Structural / size-to-algorithm-output matching (same shared
        # lookup c/go/java_buffers.py use) when a crypto call sits in the
        # same enclosing function -- never a second hand-copied size table.
        if inferred_field is None and has_crypto_api:
            inferred_field = infer_field_from_size(declared_bytes)

        # 2. Data-flow correlation: the buffer is later slice-assigned from
        # another name in the same scope (`buf[:len(x)] = x`) -- the
        # Python idiom for "copy a crypto result into this fixed buffer",
        # mirroring java_buffers.py's System.arraycopy check.
        if inferred_field is None and self._is_crypto_data_flow(name, enclosing_scope):
            inferred_field = infer_field_from_size(declared_bytes) or "signature"

        if pattern_match is None and inferred_field is None:
            return None

        evidence = Evidence(
            source_type="source",
            locator=locator,
            line=ident_node.start_point[0] + 1,
            column=ident_node.start_point[1],
            byte_offset=ident_node.start_byte,
            snippet=_text(span_node),
            detector_id=_DETECTOR_ID,
            detector_version=_DETECTOR_VERSION,
        )

        return SizeConstraint(
            kind="heap_alloc",
            name=name,
            declared_bytes=declared_bytes,
            evidence=[evidence],
            language="python",
            inferred_field=inferred_field,  # type: ignore[arg-type]
        )

    _NON_CRYPTO_RHS_IDENTIFIERS = frozenset({"True", "False", "None"})

    def _is_crypto_data_flow(self, buf_name: str, scope: Any | None) -> bool:
        """True if `buf_name` is later slice/index-assigned from another
        NAME in the same scope (`buf[:len(x)] = x`) -- the Python idiom for
        copying a crypto result into a fixed buffer, mirroring
        java_buffers.py's System.arraycopy check. The right-hand side must
        be a bare identifier, never a literal (`buf[0] = 1`) -- assigning a
        constant is not "a crypto result flowed into this buffer".
        """
        if scope is None:
            return False
        scope_text = _text(scope)
        slice_assign_pat = re.compile(rf"\b{re.escape(buf_name)}\s*\[[^\]]*\]\s*=\s*([A-Za-z_]\w*)\b")
        for match in slice_assign_pat.finditer(scope_text):
            if match.group(1) not in self._NON_CRYPTO_RHS_IDENTIFIERS:
                return True
        return False

    @staticmethod
    def _find_enclosing_function(node: Any) -> Any | None:
        curr = node.parent
        while curr is not None:
            if curr.type in ("function_definition", "class_definition"):
                return curr
            curr = curr.parent
        return None
