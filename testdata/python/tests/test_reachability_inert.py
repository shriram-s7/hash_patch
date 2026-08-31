"""
tests/test_reachability_inert.py — the ONLY caller of
`_reach_inert_helper` (testdata/python/reachability_inert.py) anywhere in
this codebase. There is no production entry point or production caller,
only this test. Lives under testdata/python/tests/, so it matches the
"path contains a test/tests directory segment" convention (and its filename
also starts with test_) — see docs/REACHABILITY.md.
"""

from testdata.python.reachability_inert import _reach_inert_helper


def test_reach_inert_helper_runs():
    assert _reach_inert_helper() is not None
