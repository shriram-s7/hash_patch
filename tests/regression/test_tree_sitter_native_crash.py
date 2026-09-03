"""tests/regression/test_tree_sitter_native_crash.py

Regression coverage for a real production incident hit scanning
pyca/cryptography end to end:

  1. ORIGINAL SYMPTOM: unbounded function-call recursion in the tree-sitter
     AST walks (`hash_patch/analyze/callgraph.py::_walk_py_calls`,
     `hash_patch/detect/shelf_life/data_context.py::_walk_python_spans`,
     `hash_patch/detect/python.py::_walk`, `hash_patch/detect/java.py::_walk`,
     `hash_patch/detect/config/source_tls_intent.py`'s two `visit` walks)
     could, on a real-world deeply-nested-expression file, raise an
     uncaught `RecursionError` that propagated straight through
     `detect()`/`run_scan()`/the CLI and aborted the ENTIRE scan over one
     pathological file. All were converted to explicit heap-allocated-stack
     walks with a `_MAX_WALK_DEPTH` cap (see each module's own comment, and
     docs/REACHABILITY.md's / docs/SHELF_LIFE.md's "Deep-nesting safety cap"
     sections) so a pathological branch is simply not descended further
     rather than crashing or hanging the process.

  2. ACTUAL ROOT CAUSE of the specific crash first reported on a full
     pyca/cryptography scan: NOT that recursion bug. Investigation (see PR
     history / session notes) showed the real crash was
     STATUS_HEAP_CORRUPTION / access violation inside `tree-sitter==0.26.0`
     itself — every faulthandler trace showed "Garbage-collecting", at
     varying/shallow frames, on files whose actual tree-sitter AST depth
     (12-16) is nowhere near recursion-exhaustion territory. Toggling only
     the `tree-sitter` core package version (grammar package held fixed at
     `tree-sitter-python==0.25.0`) directly toggled the crash: 0.26.0
     crashes, 0.25.x does not. Fix: pin `tree-sitter>=0.25,<0.26` in
     pyproject.toml (see that pin's comment for detail). This is a real
     upstream dependency regression, not a pratyaksha code bug — no amount
     of rewriting pratyaksha's own walk functions fixes it, which is why
     the second test class below scans real files via a full subprocess
     rather than asserting anything about traversal shape.

Both classes of regression need a SUBPROCESS-based test: a stack overflow
or a native access violation kills the process outright — pytest cannot
observe it as a normal exception in-process. Every test here shells out to
the installed `pratyaksha` CLI (same convention as
tests/integration/test_cli_scan.py) with a timeout and asserts a clean
`returncode == 0`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# Deliberately NOT under testdata/ — see tests/regression/fixtures/README.md:
# several unit tests scan the whole testdata/ tree as a corpus with
# hand-tuned expected outcomes, and these two real files are large enough to
# shift that corpus and break those unrelated assertions.
REGRESSION_TESTDATA_DIR = Path(__file__).resolve().parent / "fixtures"


def _hash_patch_cli_command(*args: str) -> list[str]:
    """Same venv-script-first, module-fallback resolution as
    tests/integration/test_cli_scan.py's subprocess test, so this suite is
    exercising the real installed entry point wherever possible.
    """
    parent = Path(sys.executable).parent
    for name in ["hash-patch.exe", "hashpatch.exe", "hash-patch", "hashpatch", "pratyaksha.exe", "pratyaksha"]:
        cand = parent / name
        if cand.is_file():
            return [str(cand), *args]
    return [sys.executable, "-c", "from hash_patch.cli import app; app()", *args]


# ---------------------------------------------------------------------------
# Class 1: the original recursion-depth class of bug.
#
# A genuinely deep tree-sitter AST is NOT produced by deeply nested
# if-blocks (tree-sitter's own parser hits its LR-stack limit first and
# falls back to a flat error-recovery token sequence well short of any
# depth that would stress a Python-level recursive walk) — it IS produced
# by deeply nested parenthesized expressions, which parse to a genuinely
# deep, well-formed AST. This is the shape that reproduced an uncaught
# RecursionError against the pre-fix code (caught here as a nonzero/crashed
# subprocess, never as an in-process exception).
# ---------------------------------------------------------------------------


def _write_deeply_nested_expression_file(path: Path, depth: int = 3000) -> None:
    """A single function whose body is `depth` levels of nested conditional
    expressions — generated here, not hand-written, so the test is honest
    about exercising real depth rather than a small fixed fixture.
    """
    expr = "call_target()"
    for _ in range(depth):
        expr = f"(1 if {expr} else 2)"
    path.write_text(f"def deep():\n    x = {expr}\n", encoding="utf-8")


def test_deeply_nested_expression_file_scans_without_crashing(tmp_path: Path) -> None:
    deep_file = tmp_path / "deep_nested.py"
    _write_deeply_nested_expression_file(deep_file)
    cbom_out = tmp_path / "deep_nested.cbom.json"

    completed = subprocess.run(
        _hash_patch_cli_command("scan", str(deep_file), "--output", str(cbom_out)),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, (
        "Scanning a deeply-nested-expression file must never crash the "
        f"process (recursion-depth regression). Exit code: {completed.returncode}\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )


# ---------------------------------------------------------------------------
# Class 2: the tree-sitter==0.26.0 heap-corruption regression.
#
# Scans the two real pyca/cryptography files that first surfaced the crash,
# TOGETHER as a directory (multi-file), matching the actual failure mode: a
# single full-repo scan holding many tree-sitter Node objects across
# multiple files in one process. A single-file regression test would not
# have exercised this reliably (either vendored file crashes on its own
# too, but scanning them together is the closer analogue of the original
# full-repo-scan report and avoids ever narrowing this back down to a
# "just this one file" theory).
# ---------------------------------------------------------------------------


def test_vendored_pyca_files_scan_without_crashing(tmp_path: Path) -> None:
    assert (REGRESSION_TESTDATA_DIR / "mldsa.py").is_file()
    assert (REGRESSION_TESTDATA_DIR / "pkcs7.py").is_file()

    cbom_out = tmp_path / "regression.cbom.json"

    completed = subprocess.run(
        _hash_patch_cli_command("scan", str(REGRESSION_TESTDATA_DIR), "--output", str(cbom_out)),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, (
        "Scanning the vendored real pyca/cryptography files together must "
        f"never crash the process (tree-sitter native-crash regression). "
        f"Exit code: {completed.returncode}\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    assert cbom_out.is_file(), "CLI did not write the CBOM output file"


def test_vendored_pyca_files_scan_repeatedly_without_crashing(tmp_path: Path) -> None:
    """The original crash was non-deterministic in exactly where it fired
    (varying frames across otherwise-identical runs) — a hallmark of heap
    corruption rather than a deterministic bug. One clean run is not
    sufficient evidence; repeat a few times.
    """
    for i in range(3):
        cbom_out = tmp_path / f"regression_{i}.cbom.json"
        completed = subprocess.run(
            _pratyaksha_cli_command("scan", str(REGRESSION_TESTDATA_DIR), "--output", str(cbom_out)),
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        assert completed.returncode == 0, (
            f"Run {i} crashed (non-deterministic heap corruption regression). "
            f"Exit code: {completed.returncode}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
