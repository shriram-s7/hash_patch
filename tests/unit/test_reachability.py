"""tests/unit/test_reachability.py

Unit tests for hash_patch/analyze/{callgraph,entrypoints,reachability}.py.

Section 1 exercises the four reachability corpus fixtures under
testdata/python/ and testdata/java/ (see docs/REACHABILITY.md), each with
its own explicit assertion of the exact expected classification.

Section 2 is the safety-critical suite: the HARD SAFETY RULE in CLAUDE.md
and docs/REACHABILITY.md says a live, externally-reachable crypto call must
NEVER be classified INERT, and "when in doubt, UNKNOWN, not INERT" for
anything genuinely uncertain. test_live_call_never_classified_as_inert is
the single most important test in this file.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from hash_patch.analyze.reachability import is_c_test_file, is_java_test_file, is_python_test_file
from hash_patch.cli import run_scan
from hash_patch.model.assets import Reachability

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_PY_DIR = REPO_ROOT / "testdata" / "python"
TESTDATA_JAVA_DIR = REPO_ROOT / "testdata" / "java"
TESTDATA_C_DIR = REPO_ROOT / "testdata" / "c"


def _asset_for(assets, algorithm: str, locator_suffix: str):
    for asset in assets:
        if asset.name != algorithm:
            continue
        for ev in asset.evidence:
            if ev.locator.replace("\\", "/").endswith(locator_suffix):
                return asset
    return None


# ===========================================================================
# Section 1 — the four corpus scenarios, Python and Java, each explicit.
# ===========================================================================


def test_python_corpus_live_external() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    asset = _asset_for(result.assets, "SHA-512", "reachability_live_external.py")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_EXTERNAL


def test_python_corpus_live_internal() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    asset = _asset_for(result.assets, "SHA3-256", "reachability_live_internal.py")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_INTERNAL


def test_python_corpus_inert() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    asset = _asset_for(result.assets, "ElGamal", "reachability_inert.py")
    assert asset is not None
    assert asset.reachability == Reachability.INERT


def test_python_corpus_unknown_dynamic_dispatch() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    asset = _asset_for(result.assets, "ChaCha20", "reachability_unknown_dynamic.py")
    assert asset is not None
    assert asset.reachability == Reachability.UNKNOWN


def test_java_corpus_live_external() -> None:
    result = run_scan(TESTDATA_JAVA_DIR)
    asset = _asset_for(result.assets, "SHA-512", "ReachabilityLiveExternal.java")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_EXTERNAL


def test_java_corpus_live_internal() -> None:
    result = run_scan(TESTDATA_JAVA_DIR)
    asset = _asset_for(result.assets, "SHA3-256", "ReachabilityLiveInternal.java")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_INTERNAL


def test_java_corpus_inert() -> None:
    result = run_scan(TESTDATA_JAVA_DIR)
    asset = _asset_for(result.assets, "DSA", "ReachabilityInert.java")
    assert asset is not None
    assert asset.reachability == Reachability.INERT


def test_java_corpus_unknown_dynamic_dispatch() -> None:
    result = run_scan(TESTDATA_JAVA_DIR)
    asset = _asset_for(result.assets, "DES", "ReachabilityUnknownDynamic.java")
    assert asset is not None
    assert asset.reachability == Reachability.UNKNOWN


def test_c_corpus_live_external() -> None:
    result = run_scan(TESTDATA_C_DIR)
    asset = _asset_for(result.assets, "SHA-512", "reachability_live_external.c")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_EXTERNAL


def test_c_corpus_live_internal() -> None:
    result = run_scan(TESTDATA_C_DIR)
    asset = _asset_for(result.assets, "SHA3-256", "reachability_live_internal.c")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_INTERNAL


def test_c_corpus_inert() -> None:
    result = run_scan(TESTDATA_C_DIR)
    asset = _asset_for(result.assets, "SHA-384", "reachability_inert.c")
    assert asset is not None
    assert asset.reachability == Reachability.INERT


def test_c_corpus_unknown_dynamic_dispatch() -> None:
    result = run_scan(TESTDATA_C_DIR)
    asset = _asset_for(result.assets, "SHA3-512", "reachability_unknown_dynamic.c")
    assert asset is not None
    assert asset.reachability == Reachability.UNKNOWN


def test_c_multi_hop_chain_reachable_and_blast_radius_correlated() -> None:
    """The 3-hop chain (main -> sign_entry -> sign_middle -> sign_leaf) in
    testdata/c/blast_radius_reachable_chain.c is both LIVE_EXTERNAL (real C
    call-graph resolution) AND produces a Pillar-3 blast-radius finding
    (its RSA signature buffer is too small for ML-DSA-65) — the combined
    case the blast-radius shockwave UI needs multi-node call-graph data for.
    """
    result = run_scan(TESTDATA_C_DIR)
    asset = _asset_for(result.assets, "RSA", "blast_radius_reachable_chain.c")
    assert asset is not None
    assert asset.reachability == Reachability.LIVE_EXTERNAL
    assert any(
        f.size_constraint.evidence[0].locator.replace("\\", "/").endswith(
            "blast_radius_reachable_chain.c"
        )
        for f in result.blast_radius_findings
    )


# ===========================================================================
# Section 2 — safety-critical behaviour.
# ===========================================================================


def test_live_call_never_classified_as_inert(tmp_path: Path) -> None:
    """THE SAFETY TEST.

    A genuinely live, externally-reachable RSA call, reached through TWO
    levels of indirection (entry point -> helper -> helper -> crypto call).
    Must never be classified INERT — and, since it really is reachable from
    a tagged entry point, must be LIVE_EXTERNAL.
    """
    src = textwrap.dedent(
        """
        from flask import Flask
        from Crypto.PublicKey import RSA

        app = Flask(__name__)


        def _level_two_helper():
            return RSA.generate(2048)


        def _level_one_helper():
            return _level_two_helper()


        @app.route("/x")
        def entry_point():
            return _level_one_helper()
        """
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")

    result = run_scan(tmp_path)
    rsa_assets = [a for a in result.assets if a.name == "RSA"]
    assert rsa_assets, "expected an RSA asset to be detected"
    for asset in rsa_assets:
        assert asset.reachability != Reachability.INERT, (
            "a live, externally-reachable crypto call was classified INERT — "
            "this is the single worst failure mode this feature can have"
        )
        assert asset.reachability == Reachability.LIVE_EXTERNAL


def test_unresolved_call_in_path_yields_unknown_not_inert_or_live(tmp_path: Path) -> None:
    """A crypto call reachable only through an unresolved dynamic-dispatch
    call site must be UNKNOWN — never assumed blocked (INERT) and never
    assumed reachable (LIVE_*) just because it *might* be invoked.
    """
    src = textwrap.dedent(
        """
        from Crypto.Cipher import ChaCha20


        def _crypto_helper():
            return ChaCha20.new(key=b"0" * 32)


        _DISPATCH = {"go": _crypto_helper}


        def dynamic_entry(action):
            handler = _DISPATCH[action]
            return handler()
        """
    )
    (tmp_path / "dyn.py").write_text(src, encoding="utf-8")

    result = run_scan(tmp_path)
    assets = [a for a in result.assets if a.name == "ChaCha20"]
    assert assets, "expected a ChaCha20 asset to be detected"
    for asset in assets:
        assert asset.reachability == Reachability.UNKNOWN


def test_most_live_wins_merge(tmp_path: Path) -> None:
    """One asset, one live occurrence + one dead (test-confined) occurrence:
    the asset must end up at the most-live classification (LIVE_EXTERNAL),
    never downgraded by the dead occurrence.
    """
    (tmp_path / "dead_prod.py").write_text(
        textwrap.dedent(
            """
            from Crypto.Hash import MD5


            def _dead_md5_helper():
                return MD5.new()
            """
        ),
        encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_dead.py").write_text(
        textwrap.dedent(
            """
            from dead_prod import _dead_md5_helper


            def test_dead_md5_helper():
                _dead_md5_helper()
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "live_app.py").write_text(
        textwrap.dedent(
            """
            from flask import Flask
            from Crypto.Hash import MD5

            app = Flask(__name__)


            @app.route("/x")
            def entry_point():
                return MD5.new()
            """
        ),
        encoding="utf-8",
    )

    result = run_scan(tmp_path)
    md5_assets = [a for a in result.assets if a.name == "MD5"]
    assert len(md5_assets) == 1, (
        "expected the MD5 occurrences from both files to merge into one asset "
        "(same asset identity fields)"
    )
    asset = md5_assets[0]
    assert len(asset.evidence) == 2, "expected evidence from both dead_prod.py and live_app.py"
    assert asset.reachability == Reachability.LIVE_EXTERNAL, (
        "a dead second occurrence downgraded a live first occurrence — "
        "most-live-wins merge is broken"
    )


def test_reachability_classification_is_deterministic() -> None:
    """Two scans of the same corpus must assign identical reachability to
    every asset (piggybacking on the existing determinism test pattern in
    tests/integration/test_cli_scan.py).
    """
    result_a = run_scan(TESTDATA_PY_DIR)
    result_b = run_scan(TESTDATA_PY_DIR)

    reach_a = {asset.id: asset.reachability for asset in result_a.assets}
    reach_b = {asset.id: asset.reachability for asset in result_b.assets}
    assert reach_a == reach_b

    result_a_java = run_scan(TESTDATA_JAVA_DIR)
    result_b_java = run_scan(TESTDATA_JAVA_DIR)
    reach_a_java = {asset.id: asset.reachability for asset in result_a_java.assets}
    reach_b_java = {asset.id: asset.reachability for asset in result_b_java.assets}
    assert reach_a_java == reach_b_java


# ===========================================================================
# Section 3 — test-file detection helpers.
# ===========================================================================


def test_is_python_test_file_conventions() -> None:
    assert is_python_test_file("testdata/python/tests/test_reachability_inert.py")
    assert is_python_test_file("src/test_foo.py")
    assert is_python_test_file("src/foo_test.py")
    assert is_python_test_file("pkg/tests/helpers.py")
    assert not is_python_test_file("pkg/reachability_inert.py")
    assert not is_python_test_file("pkg/contest.py")


def test_is_java_test_file_conventions() -> None:
    assert is_java_test_file("src/test/java/com/example/FooTest.java")
    assert is_java_test_file("testdata/java/ReachabilityInertTest.java")
    assert is_java_test_file("com/example/FooTests.java")
    assert not is_java_test_file("com/example/Foo.java")
    assert not is_java_test_file("com/example/Contestant.java")


def test_is_c_test_file_conventions() -> None:
    assert is_c_test_file("testdata/c/tests/test_reachability_inert.c")
    assert is_c_test_file("src/test_foo.c")
    assert is_c_test_file("src/foo_test.cpp")
    assert is_c_test_file("pkg/tests/helpers.c")
    assert not is_c_test_file("pkg/reachability_inert.c")
    assert not is_c_test_file("pkg/contest.c")
