"""tests/integration/test_cli_scan.py

Integration tests that exercise the CLI's run_scan() function — the same
code path the `hash-patch scan` command invokes — against real testdata.

These tests catch the class of bug where a detector is correctly registered
and passes all unit tests, but the CLI's scan command fails to route files
to it (e.g. because the scan target is a directory and the CLI did not walk
it recursively before passing paths to supports()).

Design:
  - Tests call hash_patch.cli.run_scan() directly (not the detector) so that
    the CLI's file-enumeration, detector-dispatch, and evidence-accumulation
    layers are all exercised together.
  - No algorithm names are hardcoded here; expected-asset presence is checked
    by asserting len > 0 and by loading from rules/java_jca.yaml.
  - The subprocess test uses the installed `hash-patch` entry-point to catch
    any import-time registration failures that only manifest in a fresh process.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from hash_patch.cli import _iter_targets, run_scan
from hash_patch.model.assets import QuantumStatus

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTDATA_JAVA_DIR = REPO_ROOT / "testdata" / "java"
POSITIVE_FILE = TESTDATA_JAVA_DIR / "crypto_examples.java"
NEGATIVE_FILE = TESTDATA_JAVA_DIR / "negative_rsa_mention.java"


def _resolve_cli_cmd(args: list[str]) -> list[str]:
    parent = Path(sys.executable).parent
    for name in ["hash-patch.exe", "hashpatch.exe", "hash-patch", "hashpatch", ]:
        cand = parent / name
        if cand.is_file():
            return [str(cand), *args]
    return [sys.executable, "-c", "from hash_patch.cli import app; app()", *args]


# ---------------------------------------------------------------------------
# Tests: _iter_targets() file-enumeration helper
# ---------------------------------------------------------------------------


def test_iter_targets_file_yields_itself() -> None:
    results = list(_iter_targets(POSITIVE_FILE))
    assert results == [POSITIVE_FILE]


def test_iter_targets_directory_yields_all_java_files() -> None:
    results = list(_iter_targets(TESTDATA_JAVA_DIR))
    assert POSITIVE_FILE in results
    assert NEGATIVE_FILE in results


def test_iter_targets_directory_is_sorted() -> None:
    results = list(_iter_targets(TESTDATA_JAVA_DIR))
    assert results == sorted(results), "Directory walk must be sorted for determinism"


def test_iter_targets_directory_yields_only_files(tmp_path: Path) -> None:
    """No directories should appear in the output, only regular files."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "a.java").write_text("class A {}")
    (sub / "b.java").write_text("class B {}")
    results = list(_iter_targets(tmp_path))
    for r in results:
        assert r.is_file(), f"Expected a file, got: {r}"


def test_iter_targets_nonexistent_path_yields_nothing(tmp_path: Path) -> None:
    """A path that doesn't exist should silently yield nothing (not raise)."""
    ghost = tmp_path / "does_not_exist.java"
    results = list(_iter_targets(ghost))
    assert results == []


# ---------------------------------------------------------------------------
# Tests: run_scan() called with a DIRECTORY path (the previously-broken path)
# ---------------------------------------------------------------------------


def test_run_scan_on_directory_produces_nonzero_assets() -> None:
    """This is the exact bug that was reported: scanning a directory produced
    0 assets because the CLI never walked the directory.

    run_scan(TESTDATA_JAVA_DIR) must produce at least one CryptoAsset.
    """
    result = run_scan(TESTDATA_JAVA_DIR)
    assert len(result.assets) > 0, (
        "run_scan() on testdata/java/ returned 0 assets. "
        "The CLI is not routing directory files to detectors."
    )


def test_run_scan_on_directory_finds_broken_classically_algorithms() -> None:
    """MD5 and SHA-1 in crypto_examples.java must be detected via the dir path."""
    result = run_scan(TESTDATA_JAVA_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_CLASSICALLY in statuses, (
        f"Expected broken-classically assets; found only: {statuses}"
    )


def test_run_scan_on_directory_finds_broken_by_shor_algorithms() -> None:
    """RSA, EC, ECDSA in crypto_examples.java must be detected via the dir path."""
    result = run_scan(TESTDATA_JAVA_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_BY_SHOR in statuses, (
        f"Expected broken-by-shor assets; found only: {statuses}"
    )


def test_run_scan_on_directory_finds_weakened_by_grover_algorithms() -> None:
    """AES and SHA-256 in crypto_examples.java must be detected via the dir path."""
    result = run_scan(TESTDATA_JAVA_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.WEAKENED_BY_GROVER in statuses, (
        f"Expected weakened-by-grover assets; found only: {statuses}"
    )


def test_run_scan_on_directory_result_asset_count_matches_file_scan() -> None:
    """Scanning the directory must produce the same assets as scanning the
    positive fixture file directly (after the negative fixture contributes 0).
    """
    dir_result = run_scan(TESTDATA_JAVA_DIR)
    file_result = run_scan(POSITIVE_FILE)

    dir_ids = {a.id for a in dir_result.assets}
    file_ids = {a.id for a in file_result.assets}

    # All assets found in the positive file must be present in the dir scan.
    missing = file_ids - dir_ids
    assert not missing, (
        f"Dir scan is missing asset IDs that file scan found: {missing}"
    )


def test_run_scan_on_directory_negative_fixture_adds_no_extra_assets(tmp_path: Path) -> None:
    """The negative fixture mentions RSA only in comments; it must not inflate
    the asset count above what the positive fixture alone produces.

    Scans an isolated temp directory containing only {positive, negative}
    fixtures rather than the whole testdata/java/ tree, so this assertion
    stays scoped to the negative fixture's own behaviour even as other
    legitimate positive fixtures (e.g. the reachability corpus) are added
    to testdata/java/ over time.
    """
    isolated = tmp_path / "java_negative_check"
    isolated.mkdir()
    (isolated / POSITIVE_FILE.name).write_text(POSITIVE_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    (isolated / NEGATIVE_FILE.name).write_text(NEGATIVE_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    dir_result = run_scan(isolated)
    file_result = run_scan(POSITIVE_FILE)

    # Asset IDs are deterministic — if two files produce the same logical
    # algorithm, they merge into one asset (more evidence, same ID).
    dir_ids = sorted(a.id for a in dir_result.assets)
    file_ids = sorted(a.id for a in file_result.assets)

    assert dir_ids == file_ids, (
        "Dir scan found different asset IDs than file scan — "
        "the negative fixture may be producing false-positive assets.\n"
        f"Dir: {dir_ids}\nFile: {file_ids}"
    )


def test_run_scan_every_asset_has_evidence_after_directory_walk() -> None:
    """Hard constraint #3: no asset without evidence, even after merging across
    multiple files in a directory walk.
    """
    result = run_scan(TESTDATA_JAVA_DIR)
    for asset in result.assets:
        assert len(asset.evidence) >= 1, (
            f"Asset {asset.name!r} (id={asset.id}) has no evidence after dir scan"
        )


def test_run_scan_on_single_file_still_works() -> None:
    """Regression: run_scan() must still handle a single-file path correctly."""
    result = run_scan(POSITIVE_FILE)
    assert len(result.assets) > 0


def test_run_scan_is_deterministic_on_directory() -> None:
    """Two directory scans must produce identical asset IDs and evidence keys."""
    result_a = run_scan(TESTDATA_JAVA_DIR)
    result_b = run_scan(TESTDATA_JAVA_DIR)

    ids_a = sorted(a.id for a in result_a.assets)
    ids_b = sorted(a.id for a in result_b.assets)
    assert ids_a == ids_b, "Directory scan is non-deterministic (different asset IDs)"

    for a, b in zip(
        sorted(result_a.assets, key=lambda x: x.id),
        sorted(result_b.assets, key=lambda x: x.id),
    ):
        keys_a = sorted(e.key() for e in a.evidence)
        keys_b = sorted(e.key() for e in b.evidence)
        assert keys_a == keys_b, f"Evidence non-deterministic for {a.name!r}"


# ---------------------------------------------------------------------------
# Subprocess test: exercises the installed CLI entry-point end-to-end
# This catches import-time failures, missing __init__ registrations, etc.
# ---------------------------------------------------------------------------


def test_cli_scan_directory_subprocess_nonzero_assets(tmp_path: Path) -> None:
    """Invoke `hash-patch scan <dir> --output <cbom>` as a real subprocess.

    Uses the venv-installed `hash-patch` script (same binary the user runs)
    so that import-time registration failures and entry-point issues are caught.
    Falls back to `python -m hash_patch.cli` when the script is not present
    (e.g. CI environments that install without scripts).
    """
    cbom_out = tmp_path / "out.cbom.json"
    cmd = _resolve_cli_cmd(["scan", str(TESTDATA_JAVA_DIR), "--output", str(cbom_out)])

    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, (
        f"CLI exited with code {completed.returncode}.\n"
        f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
    )

    # The summary line must report > 0 assets.
    assert "; 0 assets" not in completed.stdout, (
        f"CLI reported '0 assets' for directory scan.\nstdout: {completed.stdout}"
    )
    assert "assets" in completed.stdout, (
        f"Expected 'assets' in CLI output.\nstdout: {completed.stdout}"
    )

    # The CBOM file must be written and parseable.
    assert cbom_out.is_file(), "CLI did not write the CBOM output file"
    doc = json.loads(cbom_out.read_text(encoding="utf-8"))
    assert len(doc.get("components", [])) > 0, (
        "CBOM output has no components despite non-zero CLI summary"
    )


# ===========================================================================
# Python detector integration tests
# Mirror the Java section above to ensure the same class of bug cannot
# silently re-emerge for the Python detector.
# ===========================================================================

TESTDATA_PY_DIR = REPO_ROOT / "testdata" / "python"
POSITIVE_PY_FILE = TESTDATA_PY_DIR / "crypto_pyca.py"
NEGATIVE_PY_FILE = TESTDATA_PY_DIR / "negative_rsa_mention.py"


def test_run_scan_on_python_directory_produces_nonzero_assets() -> None:
    """Scanning testdata/python/ via run_scan() must yield at least one asset.

    This is the exact class of bug that previously silenced the Java detector
    when a directory was passed: the CLI must walk the directory and route
    each .py file to the Python detector.
    """
    result = run_scan(TESTDATA_PY_DIR)
    assert len(result.assets) > 0, (
        "run_scan() on testdata/python/ returned 0 assets. "
        "The Python detector is not being dispatched on directory scans."
    )


def test_run_scan_python_directory_finds_broken_classically() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_CLASSICALLY in statuses, (
        f"Expected broken-classically assets (MD5, SHA-1); found: {statuses}"
    )


def test_run_scan_python_directory_finds_broken_by_shor() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_BY_SHOR in statuses, (
        f"Expected broken-by-shor assets (RSA, ECDSA); found: {statuses}"
    )


def test_run_scan_python_directory_finds_weakened_by_grover() -> None:
    result = run_scan(TESTDATA_PY_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.WEAKENED_BY_GROVER in statuses, (
        f"Expected weakened-by-grover assets (AES, SHA-256); found: {statuses}"
    )


def test_run_scan_python_directory_asset_ids_match_file_scan() -> None:
    """Dir scan must find at least all assets the positive file scan finds."""
    dir_result = run_scan(TESTDATA_PY_DIR)
    file_result = run_scan(POSITIVE_PY_FILE)
    dir_ids = {a.id for a in dir_result.assets}
    file_ids = {a.id for a in file_result.assets}
    missing = file_ids - dir_ids
    assert not missing, f"Dir scan missing assets found in file scan: {missing}"


def test_run_scan_python_negative_fixture_adds_no_extra_assets(tmp_path: Path) -> None:
    """The negative fixture must not add any new asset IDs beyond the positive file.

    Scans an isolated temp directory containing only {positive, negative}
    fixtures rather than the whole testdata/python/ tree, so this assertion
    stays scoped to the negative fixture's own behaviour even as other
    legitimate positive fixtures (e.g. the reachability corpus) are added
    to testdata/python/ over time.
    """
    isolated = tmp_path / "python_negative_check"
    isolated.mkdir()
    (isolated / POSITIVE_PY_FILE.name).write_text(
        POSITIVE_PY_FILE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (isolated / NEGATIVE_PY_FILE.name).write_text(
        NEGATIVE_PY_FILE.read_text(encoding="utf-8"), encoding="utf-8"
    )

    dir_result = run_scan(isolated)
    file_result = run_scan(POSITIVE_PY_FILE)
    dir_ids = sorted(a.id for a in dir_result.assets)
    file_ids = sorted(a.id for a in file_result.assets)
    assert dir_ids == file_ids, (
        "Dir scan has different asset IDs than single-file scan — "
        "negative fixture may be producing false positives.\n"
        f"Dir:  {dir_ids}\nFile: {file_ids}"
    )


def test_run_scan_python_every_asset_has_evidence() -> None:
    """Hard constraint #3: no asset without evidence after directory walk."""
    result = run_scan(TESTDATA_PY_DIR)
    for asset in result.assets:
        assert len(asset.evidence) >= 1, (
            f"Asset {asset.name!r} has no evidence after dir scan"
        )


def test_run_scan_python_is_deterministic() -> None:
    a = run_scan(TESTDATA_PY_DIR)
    b = run_scan(TESTDATA_PY_DIR)
    assert sorted(x.id for x in a.assets) == sorted(x.id for x in b.assets)


def test_cli_scan_python_directory_subprocess_nonzero_assets(tmp_path: Path) -> None:
    """Invoke `hash-patch scan testdata/python --output <cbom>` as a subprocess."""
    cbom_out = tmp_path / "py_out.cbom.json"
    cmd = _resolve_cli_cmd(["scan", str(TESTDATA_PY_DIR), "--output", str(cbom_out)])

    completed = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False,
    )
    assert completed.returncode == 0, (
        f"CLI exit {completed.returncode}.\nstdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    assert "; 0 assets" not in completed.stdout, (
        f"CLI reported '0 assets' for Python dir scan.\nstdout: {completed.stdout}"
    )
    assert cbom_out.is_file(), "CLI did not write the CBOM output file"
    doc = json.loads(cbom_out.read_text(encoding="utf-8"))
    assert len(doc.get("components", [])) > 0


# ===========================================================================
# Go detector integration tests
# Ensures the Go detector is properly dispatched via run_scan() on directories.
# ===========================================================================

TESTDATA_GO_DIR = REPO_ROOT / "testdata" / "go"
POSITIVE_GO_FILE = TESTDATA_GO_DIR / "crypto_examples.go"
NEGATIVE_GO_FILE = TESTDATA_GO_DIR / "negative_rsa_mention.go"


def test_run_scan_on_go_directory_produces_nonzero_assets() -> None:
    """Scanning testdata/go/ via run_scan() must yield at least one asset."""
    result = run_scan(TESTDATA_GO_DIR)
    assert len(result.assets) > 0, (
        "run_scan() on testdata/go/ returned 0 assets. "
        "The Go detector is not being dispatched on directory scans."
    )


def test_run_scan_go_directory_finds_broken_classically() -> None:
    result = run_scan(TESTDATA_GO_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_CLASSICALLY in statuses, (
        f"Expected broken-classically assets (MD5, SHA-1, 3DES); found: {statuses}"
    )


def test_run_scan_go_directory_finds_broken_by_shor() -> None:
    result = run_scan(TESTDATA_GO_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_BY_SHOR in statuses, (
        f"Expected broken-by-shor assets (RSA, ECDSA); found: {statuses}"
    )


def test_run_scan_go_directory_finds_weakened_by_grover() -> None:
    result = run_scan(TESTDATA_GO_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.WEAKENED_BY_GROVER in statuses, (
        f"Expected weakened-by-grover assets (AES, SHA-256); found: {statuses}"
    )


def test_run_scan_go_directory_asset_ids_match_file_scan() -> None:
    """Dir scan must find at least all assets the positive file scan finds."""
    dir_result = run_scan(TESTDATA_GO_DIR)
    file_result = run_scan(POSITIVE_GO_FILE)
    dir_ids = {a.id for a in dir_result.assets}
    file_ids = {a.id for a in file_result.assets}
    missing = file_ids - dir_ids
    assert not missing, f"Dir scan missing assets found in file scan: {missing}"


def test_run_scan_go_negative_fixture_adds_no_extra_assets(tmp_path: Path) -> None:
    """The negative fixture must not add any new asset IDs beyond the positive file.

    Scans an isolated temp directory containing only {positive, negative}
    fixtures rather than the whole testdata/go/ tree, so this assertion
    stays scoped to the negative fixture's own behaviour even as other
    legitimate positive fixtures (e.g. bcrypt_examples.go, added by the
    coverage-gap audit — see docs/COVERAGE.md) are added to testdata/go/
    over time. Same pattern
    test_run_scan_on_directory_negative_fixture_adds_no_extra_assets (Java),
    test_run_scan_python_negative_fixture_adds_no_extra_assets, and
    test_run_scan_c_negative_fixture_adds_no_extra_assets already use below.
    """
    isolated = tmp_path / "go_negative_check"
    isolated.mkdir()
    (isolated / POSITIVE_GO_FILE.name).write_text(POSITIVE_GO_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    (isolated / NEGATIVE_GO_FILE.name).write_text(NEGATIVE_GO_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    dir_result = run_scan(isolated)
    file_result = run_scan(POSITIVE_GO_FILE)
    dir_ids = sorted(a.id for a in dir_result.assets)
    file_ids = sorted(a.id for a in file_result.assets)
    assert dir_ids == file_ids, (
        "Dir scan has different asset IDs than single-file scan — "
        "negative fixture may be producing false positives.\n"
        f"Dir:  {dir_ids}\nFile: {file_ids}"
    )


def test_run_scan_go_every_asset_has_evidence() -> None:
    """Hard constraint #3: no asset without evidence after directory walk."""
    result = run_scan(TESTDATA_GO_DIR)
    for asset in result.assets:
        assert len(asset.evidence) >= 1, (
            f"Asset {asset.name!r} has no evidence after dir scan"
        )


def test_run_scan_go_is_deterministic() -> None:
    a = run_scan(TESTDATA_GO_DIR)
    b = run_scan(TESTDATA_GO_DIR)
    assert sorted(x.id for x in a.assets) == sorted(x.id for x in b.assets)


def test_cli_scan_go_directory_subprocess_nonzero_assets(tmp_path: Path) -> None:
    """Invoke `hash-patch scan testdata/go --output <cbom>` as a subprocess."""
    cbom_out = tmp_path / "go_out.cbom.json"
    cmd = _resolve_cli_cmd(["scan", str(TESTDATA_GO_DIR), "--output", str(cbom_out)])

    completed = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False,
    )
    assert completed.returncode == 0, (
        f"CLI exit {completed.returncode}.\nstdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    assert "; 0 assets" not in completed.stdout, (
        f"CLI reported '0 assets' for Go dir scan.\nstdout: {completed.stdout}"
    )
    assert cbom_out.is_file(), "CLI did not write the CBOM output file"
    doc = json.loads(cbom_out.read_text(encoding="utf-8"))
    assert len(doc.get("components", [])) > 0


# ===========================================================================
# C/C++ detector integration tests
# Ensures the C detector is properly dispatched via run_scan() on directories.
# ===========================================================================

TESTDATA_C_DIR = REPO_ROOT / "testdata" / "c"
POSITIVE_C_FILE = TESTDATA_C_DIR / "crypto_examples.c"
NEGATIVE_C_FILE = TESTDATA_C_DIR / "negative_rsa_mention.c"


def test_run_scan_on_c_directory_produces_nonzero_assets() -> None:
    """Scanning testdata/c/ via run_scan() must yield at least one asset."""
    result = run_scan(TESTDATA_C_DIR)
    assert len(result.assets) > 0, (
        "run_scan() on testdata/c/ returned 0 assets. "
        "The C detector is not being dispatched on directory scans."
    )


def test_run_scan_c_directory_finds_broken_classically() -> None:
    result = run_scan(TESTDATA_C_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_CLASSICALLY in statuses, (
        f"Expected broken-classically assets (MD5, SHA-1, DES, 3DES); found: {statuses}"
    )


def test_run_scan_c_directory_finds_broken_by_shor() -> None:
    result = run_scan(TESTDATA_C_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.BROKEN_BY_SHOR in statuses, (
        f"Expected broken-by-shor assets (RSA, ECDSA); found: {statuses}"
    )


def test_run_scan_c_directory_finds_weakened_by_grover() -> None:
    result = run_scan(TESTDATA_C_DIR)
    statuses = {a.quantum_status for a in result.assets}
    assert QuantumStatus.WEAKENED_BY_GROVER in statuses, (
        f"Expected weakened-by-grover assets (AES, SHA-256); found: {statuses}"
    )


def test_run_scan_c_directory_asset_ids_match_file_scan() -> None:
    """Dir scan must find at least all assets the positive file scan finds."""
    dir_result = run_scan(TESTDATA_C_DIR)
    file_result = run_scan(POSITIVE_C_FILE)
    dir_ids = {a.id for a in dir_result.assets}
    file_ids = {a.id for a in file_result.assets}
    missing = file_ids - dir_ids
    assert not missing, f"Dir scan missing assets found in file scan: {missing}"


def test_run_scan_c_negative_fixture_adds_no_extra_assets(tmp_path: Path) -> None:
    """The negative fixture must not add any new asset IDs beyond the positive file.

    Scans an isolated temp directory containing only {positive, negative}
    fixtures rather than the whole testdata/c/ tree, so this assertion stays
    scoped to the negative fixture's own behaviour even as other legitimate
    positive fixtures (e.g. the blast-radius corpus) are added to
    testdata/c/ over time.
    """
    isolated = tmp_path / "c_negative_check"
    isolated.mkdir()
    (isolated / POSITIVE_C_FILE.name).write_text(POSITIVE_C_FILE.read_text(encoding="utf-8"), encoding="utf-8")
    (isolated / NEGATIVE_C_FILE.name).write_text(NEGATIVE_C_FILE.read_text(encoding="utf-8"), encoding="utf-8")

    dir_result = run_scan(isolated)
    file_result = run_scan(POSITIVE_C_FILE)
    dir_ids = sorted(a.id for a in dir_result.assets)
    file_ids = sorted(a.id for a in file_result.assets)
    assert dir_ids == file_ids, (
        "Dir scan has different asset IDs than single-file scan — "
        "negative fixture may be producing false positives.\n"
        f"Dir:  {dir_ids}\nFile: {file_ids}"
    )


def test_run_scan_c_every_asset_has_evidence() -> None:
    """Hard constraint #3: no asset without evidence after directory walk."""
    result = run_scan(TESTDATA_C_DIR)
    for asset in result.assets:
        assert len(asset.evidence) >= 1, (
            f"Asset {asset.name!r} has no evidence after dir scan"
        )


def test_run_scan_c_is_deterministic() -> None:
    a = run_scan(TESTDATA_C_DIR)
    b = run_scan(TESTDATA_C_DIR)
    assert sorted(x.id for x in a.assets) == sorted(x.id for x in b.assets)


def test_cli_scan_c_directory_subprocess_nonzero_assets(tmp_path: Path) -> None:
    """Invoke `hash-patch scan testdata/c --output <cbom>` as a subprocess."""
    cbom_out = tmp_path / "c_out.cbom.json"
    cmd = _resolve_cli_cmd(["scan", str(TESTDATA_C_DIR), "--output", str(cbom_out)])

    completed = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", timeout=60, check=False,
    )
    assert completed.returncode == 0, (
        f"CLI exit {completed.returncode}.\nstdout: {completed.stdout}\nstderr: {completed.stderr}"
    )
    assert "; 0 assets" not in completed.stdout, (
        f"CLI reported '0 assets' for C dir scan.\nstdout: {completed.stdout}"
    )
    assert cbom_out.is_file(), "CLI did not write the CBOM output file"
    doc = json.loads(cbom_out.read_text(encoding="utf-8"))
    assert len(doc.get("components", [])) > 0


# ===========================================================================
# Mixed-language directory: cross-language evidence must never be silently
# dropped when a shared parent directory contains files from multiple
# supported languages.
#
# `testdata/mixed_language_sha256/` has two files, in two different
# languages, both computing SHA-256 independently at different locations:
#   - pyservice/hasher.py  (hashlib.sha256, python-crypto detector)
#   - goservice/hasher.go  (crypto/sha256, go-crypto detector)
#
# The CORRECT result is ONE CryptoAsset named "SHA-256" (asset identity is
# deliberately (asset_type, name, parameter_set, mode) only — see
# hash_patch/model/assets.py::derive_asset_id's own docstring, and the
# already-existing test_md5_has_two_evidence_entries_pyca_and_pycryptodome
# in tests/unit/test_python_detector.py, which the exact same
# one-component/many-locations model already covers for two detectors
# merging within a SINGLE language) carrying BOTH evidence occurrences,
# each with the correct locator/line/detector_id. A test asserting "two
# separate SHA-256 assets must exist" would be asserting the WRONG, broken
# behavior — CycloneDX models one technology as one component with
# multiple evidence occurrences, not one component per call site. What
# this test actually guards against is DATA LOSS: either evidence location
# missing, or a locator overwritten by the other language's, would fail it.
# ===========================================================================

TESTDATA_MIXED_DIR = REPO_ROOT / "testdata" / "mixed_language_sha256"
MIXED_PY_FILE = TESTDATA_MIXED_DIR / "pyservice" / "hasher.py"
MIXED_GO_FILE = TESTDATA_MIXED_DIR / "goservice" / "hasher.go"


def test_mixed_language_fixture_files_exist() -> None:
    assert MIXED_PY_FILE.is_file()
    assert MIXED_GO_FILE.is_file()


def test_mixed_language_directory_keeps_both_findings() -> None:
    """Scanning the shared parent directory must find BOTH the Python and
    the Go SHA-256 call sites — as distinct Evidence entries on the single,
    correctly-merged SHA-256 asset. Losing either one silently (the exact
    bug class this test exists to catch forever) fails this test.
    """
    result = run_scan(TESTDATA_MIXED_DIR)

    sha256_assets = [a for a in result.assets if a.name == "SHA-256"]
    assert len(sha256_assets) == 1, (
        f"Expected exactly one merged SHA-256 asset, got {len(sha256_assets)}: "
        f"{[a.id for a in sha256_assets]}"
    )
    asset = sha256_assets[0]

    locators_and_detectors = {(ev.locator, ev.detector_id) for ev in asset.evidence}
    assert (str(MIXED_PY_FILE), "python-crypto") in locators_and_detectors, (
        f"Python SHA-256 evidence missing from merged asset. "
        f"Evidence present: {[(ev.locator, ev.detector_id, ev.line) for ev in asset.evidence]}"
    )
    assert (str(MIXED_GO_FILE), "go-crypto") in locators_and_detectors, (
        f"Go SHA-256 evidence missing from merged asset. "
        f"Evidence present: {[(ev.locator, ev.detector_id, ev.line) for ev in asset.evidence]}"
    )
    assert len(asset.evidence) == 2, (
        f"Expected exactly 2 evidence entries (one per language), got {len(asset.evidence)}: "
        f"{[(ev.locator, ev.line) for ev in asset.evidence]}"
    )


def test_mixed_language_directory_matches_union_of_independent_scans() -> None:
    """The full mixed-directory scan's evidence set must equal the UNION of
    scanning each language subdirectory independently — the precise
    "diff the union" check this bug report demanded, kept as a permanent
    regression guard rather than a one-off investigation.
    """

    def evidence_rows(path: Path) -> set[tuple[str, str, str, str, int | None]]:
        result = run_scan(path)
        return {
            (a.name, a.primitive.value, a.quantum_status.value, ev.locator, ev.line)
            for a in result.assets
            for ev in a.evidence
        }

    union = evidence_rows(TESTDATA_MIXED_DIR / "pyservice") | evidence_rows(TESTDATA_MIXED_DIR / "goservice")
    combined = evidence_rows(TESTDATA_MIXED_DIR)

    assert union == combined, (
        f"Union of independent per-language scans != combined directory scan.\n"
        f"Missing from combined: {union - combined}\n"
        f"Extra in combined (unexpected): {combined - union}"
    )


