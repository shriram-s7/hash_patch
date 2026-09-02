# tests/regression/fixtures

Vendored real-world files used only to regression-test the tree-sitter
native-crash fix (see `tests/regression/test_tree_sitter_native_crash.py`
and the "Deep-nesting safety cap" sections of `docs/REACHABILITY.md` /
`docs/SHELF_LIFE.md`).

Deliberately kept OUTSIDE `testdata/`: several unit tests (e.g.
`tests/unit/test_optimizer.py::_scan_testdata_to_candidates`,
`tests/unit/test_benchmark.py`, `tests/unit/test_contradictions.py`) scan
the entire `testdata/` tree as a hand-tuned, stable corpus and assert
specific outcomes against it (e.g. "the optimiser beats the naive baseline
at budget=5.0 on this exact corpus"). These two real, fairly large
third-party files carry enough of their own crypto findings to shift that
corpus's composition and silently break those unrelated assertions — this
was caught by running the full suite after first vendoring them under
`testdata/regression/` and seeing `test_optimizer_diverges_from_naive_at_the_documented_demo_budget`
start failing. Living under `tests/regression/fixtures/` instead keeps them
scoped to only the test that means to use them.

- `mldsa.py`, `pkcs7.py` — copied verbatim from
  [`pyca/cryptography`](https://github.com/pyca/cryptography)
  (`cryptography/hazmat/primitives/asymmetric/mldsa.py` and
  `cryptography/hazmat/primitives/serialization/pkcs7.py`), dual-licensed
  Apache-2.0 / BSD per that project's own `LICENSE` — each file's own
  license header is preserved unmodified. These are the two files on which
  the `tree-sitter==0.26.0` heap-corruption bug (see pyproject.toml's
  `tree-sitter` pin comment) was first confirmed; they are scanned together
  as a directory in the regression test specifically because the crash's
  practical trigger is "enough live tree-sitter Node objects at once," which
  a multi-file scan reaches more reliably than either file alone.
