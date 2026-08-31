"""pratyaksha/analyze/entrypoints.py — config-driven entry-point tagging.

Consumes the FunctionInfo metadata pratyaksha/analyze/callgraph.py already
collected (decorators, class/method annotations, main-method shape) and the
patterns in rules/entrypoints.yaml to decide which functions/methods are
"tagged entry points" for reachability purposes.

See docs/REACHABILITY.md for the authoritative, human-readable definition of
what counts as an entry point and — just as importantly — what does not.
Nothing here is hardcoded beyond structural language shape (e.g. "a Python
`if __name__ == \"__main__\":` block" or "a Java method named exactly `main`
that is `public static` with one parameter" are language syntax, not crypto
or entry-point *names*); every actual name/annotation list lives in the YAML
so it can be extended without touching this file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pratyaksha.analyze.callgraph import FunctionId, FunctionInfo

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "rules" / "entrypoints.yaml"


def load_entrypoint_config(path: Path = _DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def tag_python_entrypoints(
    functions: list[FunctionInfo], config: dict[str, Any]
) -> set[FunctionId]:
    cfg = config.get("python", {}) or {}
    decorator_names = set(cfg.get("decorator_names", []))
    main_function_names = set(cfg.get("main_function_names", []))
    tag_main_block = bool(cfg.get("tag_main_block", False))

    tagged: set[FunctionId] = set()
    for fn in functions:
        if fn.is_synthetic_main_block:
            if tag_main_block:
                tagged.add(fn.id)
            continue
        if any(d in decorator_names for d in fn.decorators):
            tagged.add(fn.id)
            continue
        if fn.id.simple_name in main_function_names:
            tagged.add(fn.id)
    return tagged


def tag_java_entrypoints(functions: list[FunctionInfo], config: dict[str, Any]) -> set[FunctionId]:
    cfg = config.get("java", {}) or {}
    class_annotation_names = set(cfg.get("class_annotation_names", []))
    method_annotation_names = set(cfg.get("method_annotation_names", []))
    servlet_class_annotation_names = set(cfg.get("servlet_class_annotation_names", []))
    servlet_method_names = set(cfg.get("servlet_method_names", []))
    tag_main_method = bool(cfg.get("tag_main_method", False))

    tagged: set[FunctionId] = set()
    for fn in functions:
        if (
            tag_main_method
            and fn.id.simple_name == "main"
            and fn.is_static
            and fn.param_count == 1
        ):
            tagged.add(fn.id)
            continue
        if any(a in method_annotation_names for a in fn.annotations):
            tagged.add(fn.id)
            continue
        if fn.id.simple_name in servlet_method_names and any(
            a in servlet_class_annotation_names for a in fn.class_annotations
        ):
            tagged.add(fn.id)
            continue
        # A class-level web-framework annotation (@RestController, @Controller)
        # tags every PUBLIC method of that class — not private helpers — as a
        # potential entry point. Real Spring only auto-maps methods carrying
        # their own routing annotation, but this tool is a fail-safe security
        # scanner, not a runtime router: over-tagging a public controller
        # method as reachable is the safe direction (more LIVE_EXTERNAL, never
        # more INERT); under-tagging it is not. See docs/REACHABILITY.md.
        if fn.is_public and any(a in class_annotation_names for a in fn.class_annotations):
            tagged.add(fn.id)
            continue
    return tagged
