"""hash_patch/analyze/reachability.py — reachability classification.

Classifies every CryptoAsset found by the Python, Java, and C/C++ detectors
as LIVE_EXTERNAL, LIVE_INTERNAL, INERT, or UNKNOWN, by walking the call
graph (hash_patch/analyze/callgraph.py) from each evidence occurrence's
enclosing function, checking it against the tagged entry points
(hash_patch/analyze/entrypoints.py).

**HARD SAFETY RULE (non-negotiable): this analysis is fail-safe. A live,
externally-reachable crypto call must NEVER be classified INERT. Whenever
reachability genuinely cannot be determined, the answer is UNKNOWN, never
INERT.** See docs/REACHABILITY.md for the full rationale and the exact
entry-point / test-file definitions this module relies on.

Go is out of scope for this module entirely (see the one-line comment in
hash_patch/detect/go.py) — its assets simply never reach
`apply_reachability` and keep the model's default
`CryptoAsset.reachability = UNKNOWN`.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath

from hash_patch.analyze.callgraph import (
    _C_SOURCE_EXTENSIONS,
    CallGraph,
    FunctionId,
    build_c_call_graph,
    build_java_call_graph,
    build_python_call_graph,
)
from hash_patch.analyze.entrypoints import (
    load_entrypoint_config,
    tag_c_entrypoints,
    tag_java_entrypoints,
    tag_python_entrypoints,
)
from hash_patch.model.assets import CryptoAsset, Reachability
from hash_patch.model.evidence import Evidence

_RANK: dict[Reachability, int] = {
    Reachability.INERT: 0,
    Reachability.UNKNOWN: 1,
    Reachability.LIVE_INTERNAL: 2,
    Reachability.LIVE_EXTERNAL: 3,
}

TestFileClassifier = Callable[[str], bool]


def _normalized_parts(locator: str) -> tuple[str, ...]:
    return PurePosixPath(locator.replace("\\", "/")).parts


def is_python_test_file(locator: str) -> bool:
    """Python test-file convention (see docs/REACHABILITY.md):

    path contains a `test` or `tests` directory segment, OR the filename
    starts with `test_` or ends with `_test.py`.
    """
    p = PurePosixPath(locator.replace("\\", "/"))
    if "test" in p.parts or "tests" in p.parts:
        return True
    name = p.name
    return name.startswith("test_") or name.endswith("_test.py")


def is_java_test_file(locator: str) -> bool:
    """Java test-file convention (see docs/REACHABILITY.md):

    path contains a `test` directory segment (matches Maven/Gradle-style
    `src/test/java/...` layouts), OR the filename ends with `Test.java` or
    `Tests.java`.
    """
    p = PurePosixPath(locator.replace("\\", "/"))
    if "test" in p.parts:
        return True
    name = p.name
    return name.endswith(("Test.java", "Tests.java"))


def is_c_test_file(locator: str) -> bool:
    """C/C++ test-file convention (mirrors the Python/Java rules above,
    the closest real-world equivalents this codebase already has -- there
    is no single dominant C test-framework layout convention the way
    pytest/JUnit have one):

    path contains a `test` or `tests` directory segment, OR the filename
    starts with `test_` or ends with `_test.c`/`_test.cpp`/`_test.cc`/
    `_test.cxx`.
    """
    p = PurePosixPath(locator.replace("\\", "/"))
    if "test" in p.parts or "tests" in p.parts:
        return True
    name = p.name
    return name.startswith("test_") or name.endswith(
        ("_test.c", "_test.cpp", "_test.cc", "_test.cxx")
    )


class ReachabilityContext:
    """One language's call graph + tagged entry points + test-file rule,
    bundled together so `classify_occurrence` is a pure function of them.
    """

    def __init__(
        self, graph: CallGraph, entrypoints: set[FunctionId], is_test_file: TestFileClassifier
    ) -> None:
        self.graph = graph
        self.entrypoints = entrypoints
        self.is_test_file = is_test_file

    def classify_occurrence(self, locator: str, line: int | None) -> Reachability:
        if line is None:
            return Reachability.UNKNOWN

        func = self.graph.enclosing_function(locator, line)
        if func is None:
            # Evidence line could not be mapped to any known function body
            # (e.g. module-level code outside any function/main-block) —
            # we cannot determine reachability, so never guess.
            return Reachability.UNKNOWN

        if func in self.entrypoints:
            return Reachability.LIVE_EXTERNAL

        ancestors = self.graph.ancestors(func)
        if ancestors & self.entrypoints:
            return Reachability.LIVE_EXTERNAL

        non_test_ancestors = {a for a in ancestors if not self.is_test_file(a.file)}
        if non_test_ancestors:
            return Reachability.LIVE_INTERNAL

        # No path to a tagged entry point, and (if reachable at all) only via
        # test-file callers. Confirm test-confinement before ever considering
        # INERT: either the function itself lives in a test file, or every one
        # of its (possibly zero) callers does.
        test_confined = self.is_test_file(func.file) or (
            bool(ancestors) and all(self.is_test_file(a.file) for a in ancestors)
        )
        if test_confined:
            return Reachability.INERT

        # Not reachable from anything we can prove, and not confined to test
        # code either: this is exactly the case the hard safety rule is
        # about. We cannot rule out that this function is invoked through
        # something our simple, name-based resolver could not follow (a
        # dynamic dispatch table, reflection, an unresolved import) — so we
        # refuse to call it dead. UNKNOWN, never INERT.
        return Reachability.UNKNOWN


def classify_asset(asset: CryptoAsset, contexts: dict[str, ReachabilityContext]) -> Reachability:
    """Classify one asset from the most-live classification across ALL of its
    evidence occurrences (LIVE_EXTERNAL > LIVE_INTERNAL > UNKNOWN > INERT), so
    a dead second occurrence never downgrades a live first one.

    Evidence from a language with no ReachabilityContext (Go, C, or any
    non-"source" evidence such as binary/container/config/network) casts no
    vote at all — it neither raises nor lowers the result — the surviving
    `CryptoAsset.reachability` default (UNKNOWN) is used for those languages
    entirely on the CLI wiring side; this function only ever raises the rank
    from whatever untouched votes remain.
    """
    best = Reachability.INERT
    for ev in asset.evidence:
        label = _classify_evidence(ev, contexts)
        if label is None:
            continue
        if _RANK[label] > _RANK[best]:
            best = label
    return best


def _classify_evidence(ev: Evidence, contexts: dict[str, ReachabilityContext]) -> Reachability | None:
    if ev.source_type != "source":
        # Non-source evidence carries no call-graph position to walk from.
        # Explicit UNKNOWN, not silence: we genuinely don't know, and must
        # never let that translate into an implicit INERT.
        return Reachability.UNKNOWN
    suffix = PurePosixPath(ev.locator.replace("\\", "/")).suffix.lower()
    ctx = contexts.get(suffix)
    if ctx is None:
        return None
    return ctx.classify_occurrence(ev.locator, ev.line)


def build_reachability_contexts(scanned_files: Sequence[Path]) -> dict[str, ReachabilityContext]:
    """Build one `ReachabilityContext` (call graph + tagged entry points +
    test-file rule) per language present in `scanned_files`, keyed by file
    suffix (".py" / ".java"). Extracted from `apply_reachability` so other
    analyses (e.g. hash_patch/analyze/call_relations.py) can reuse the exact
    same call graph rather than re-parsing the file set from scratch.
    """
    python_files = [f for f in scanned_files if f.suffix.lower() == ".py"]
    java_files = [f for f in scanned_files if f.suffix.lower() == ".java"]
    c_files = [f for f in scanned_files if f.suffix.lower() in _C_SOURCE_EXTENSIONS]
    if not python_files and not java_files and not c_files:
        return {}

    config = load_entrypoint_config()
    contexts: dict[str, ReachabilityContext] = {}

    if python_files:
        graph = build_python_call_graph(python_files)
        entrypoints = tag_python_entrypoints(graph.function_infos, config)
        contexts[".py"] = ReachabilityContext(graph, entrypoints, is_python_test_file)

    if java_files:
        graph = build_java_call_graph(java_files)
        entrypoints = tag_java_entrypoints(graph.function_infos, config)
        contexts[".java"] = ReachabilityContext(graph, entrypoints, is_java_test_file)

    if c_files:
        # One call graph spans EVERY C/C++ source extension together (a
        # single scan target can mix .c and .cpp), same "whole file set"
        # rule as Python/Java -- see module docstring.
        graph = build_c_call_graph(c_files)
        entrypoints = tag_c_entrypoints(graph.function_infos, config)
        ctx = ReachabilityContext(graph, entrypoints, is_c_test_file)
        for ext in _C_SOURCE_EXTENSIONS:
            contexts[ext] = ctx

    return contexts


def apply_reachability_with_contexts(
    assets: list[CryptoAsset], contexts: dict[str, ReachabilityContext]
) -> None:
    """Classify reachability in place given already-built contexts (see
    `build_reachability_contexts`). Assets with no evidence matching any
    context's language are left untouched at the model default.
    """
    for asset in assets:
        best = Reachability.INERT
        has_vote = False
        for ev in asset.evidence:
            label = _classify_evidence(ev, contexts)
            if label is None:
                continue
            has_vote = True
            if _RANK[label] > _RANK[best]:
                best = label
        if has_vote:
            asset.reachability = best


def apply_reachability(assets: list[CryptoAsset], scanned_files: Sequence[Path]) -> None:
    """Classify reachability in place for every asset with Python, Java,
    and/or C/C++ evidence, using ONE directory-level call graph per
    language built from every file of that language in `scanned_files`
    (Step 1: per file *set*, not per file).

    Assets with no Python/Java/C evidence at all (pure Go findings, or C
    evidence confined to a header with no function body) are left
    untouched at the model default (`Reachability.UNKNOWN`). Convenience
    wrapper around `build_reachability_contexts` +
    `apply_reachability_with_contexts` for callers that don't need the
    contexts themselves; `hash_patch/cli.py::run_scan` calls the two-step
    form directly so it can reuse the same contexts for call-relation
    extraction (hash_patch/analyze/call_relations.py).
    """
    contexts = build_reachability_contexts(scanned_files)
    apply_reachability_with_contexts(assets, contexts)
