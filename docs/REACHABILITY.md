# Reachability classification

Hash Patch classifies every crypto-asset finding from the Python, Java, and
C/C++ detectors into one of four `CryptoAsset.reachability` values:

| Value            | Meaning                                                                 |
|-------------------|--------------------------------------------------------------------------|
| `LIVE_EXTERNAL`   | Reachable via a call chain from a tagged entry point.                   |
| `LIVE_INTERNAL`   | Reachable from some function in the codebase, but not from a tagged entry point. |
| `INERT`           | Not reachable from anything — dead code, or reachable only from a test file. |
| `UNKNOWN`         | Reachability could not be determined (dynamic dispatch, reflection, unresolved import, an unmapped evidence location, etc.). |

**Go is out of scope.** Its detector (`hash_patch/detect/go.py`) is not
wired to this analysis; its assets keep the model's default
`Reachability.UNKNOWN` unconditionally. See the one-line comment on that
detector class.

C/C++ evidence confined to a header file (`.h`/`.hpp`/`.hh`) also keeps the
model default — headers only ever contain declarations/prototypes, never a
function *body* to walk a call graph from. Evidence in an actual C/C++
source file (`.c`/`.cpp`/`.cc`/`.cxx`) is classified the same as
Python/Java.

## HARD SAFETY RULE

**This analysis is fail-safe. A live, externally-reachable crypto call must
NEVER be classified INERT. Whenever reachability genuinely cannot be
determined, the answer is UNKNOWN, never INERT.**

Getting this backwards — telling a security reviewer a live cryptographic
call is dead code — is the single worst failure mode this feature can have.
Every design decision below is biased toward UNKNOWN over INERT whenever
there is any doubt. `tests/unit/test_reachability.py::test_live_call_never_classified_as_inert`
exists specifically to guard this rule with a two-level-indirection case.

## Pipeline

1. **Call graph** (`hash_patch/analyze/callgraph.py`) — for one *file set*
   (every Python file, every Java file, or every C/C++ *source* file — not
   header — under one scan target — not per file, so cross-file calls
   within the same target resolve), build a name-based call graph: one node
   per function/method definition, one edge per call site that resolves to
   exactly one function definition in the set. A call that cannot be
   resolved to exactly one definition (a call through a variable/function
   pointer, a call into a library with no source in the set, an ambiguous
   name shared by two definitions — e.g. two files each defining a
   same-named `static` C function — any call whose target isn't a plain
   identifier or `identifier.identifier` shape) is recorded as an
   **unresolved** call on the calling function — never silently dropped.

   Name resolution is deliberately as simple as the existing detectors
   (`hash_patch/detect/python.py`, `hash_patch/detect/java.py`,
   `hash_patch/detect/c.py`), which do plain identifier matching with no
   import aliasing or type inference — there is no separate "resolver"
   module elsewhere in this codebase to reuse, so this module matches that
   level of sophistication rather than inventing a fancier one. C's graph
   is flat (no classes/methods): a function's identity is just its bare
   name, so the ambiguous-name-is-unresolved rule above is what keeps two
   unrelated same-named `static` functions in different files from being
   cross-wired.

2. **Entry-point tagging** (`hash_patch/analyze/entrypoints.py`, patterns in
   `rules/entrypoints.yaml`) — see below.

3. **Test-file detection** — see below.

4. **Classification** (`hash_patch/analyze/reachability.py`) — for each
   evidence occurrence, map its `(file, line)` to the enclosing function in
   the call graph (unmapped -> `UNKNOWN`), then:
   - the function *is* a tagged entry point, or a tagged entry point is
     among its ancestors (reverse call-graph walk) -> `LIVE_EXTERNAL`
   - it has an ancestor that is not itself confined to a test file ->
     `LIVE_INTERNAL`
   - its only path to being called at all is through test-file functions
     (or it has no callers and sits directly in a test file) -> `INERT`
   - anything else — not reachable from anything we can prove, and not
     confined to test code — -> `UNKNOWN` (never `INERT`)

   An asset with evidence in multiple locations takes the **most-live**
   classification across all of them: `LIVE_EXTERNAL` > `LIVE_INTERNAL` >
   `UNKNOWN` > `INERT`. A dead second occurrence never downgrades a live
   first one.

## What counts as a tagged entry point

Config-driven via `rules/entrypoints.yaml` — extend the list there, not the
Python code in `analyze/`.

**Python:**
- A function decorated with `@<anything>.<name>(...)` or `@<name>(...)`
  where `<name>` (the decorator expression's final identifier) is one of
  `route`, `get`, `post`, `put`, `delete`, `patch`, `websocket`, `api_view`
  — covers Flask (`@app.route`, `@app.get`/`post`/`put`/`delete`), FastAPI
  (`@app.get`/`post`/`put`/`delete`/`patch`/`websocket`), and Django REST
  Framework (`@api_view`).
- The `if __name__ == "__main__":` block, matched structurally (a synthetic
  entry-point node is created for it) — everything it directly calls is
  entry-point-reachable.
- Any module-level function named exactly `main`.

**Java:**
- `public static void main(String[] args)` (checked structurally: static,
  named `main`, exactly one parameter).
- A method annotated with `@GetMapping`, `@PostMapping`, `@PutMapping`,
  `@DeleteMapping`, `@PatchMapping`, or `@RequestMapping`.
- A method named `doGet`/`doPost`/`doPut`/`doDelete` on a class annotated
  `@WebServlet`.
- **Every `public` method of a class annotated `@RestController` or
  `@Controller`** — not just methods carrying their own routing annotation,
  and not `private`/package-private helpers. This is deliberately broader
  than real Spring routing (which only auto-maps annotated methods): this
  tool is a fail-safe security scanner, not a runtime router, and
  over-tagging a public controller method as reachable is the *safe*
  direction (more `LIVE_EXTERNAL`, never more `INERT`) — under-tagging it
  is not.

**C/C++:**
- A function named exactly `main` (the conventional C program entry
  point). C has no decorator/annotation convention comparable to
  Python/Java's routing patterns, so this is deliberately the only C rule
  for now — extend `rules/entrypoints.yaml`'s `c:` section if a real
  codebase needs another convention recognized (e.g. a specific plugin
  ABI's exported symbol names).

## What does NOT count as an entry point

Anything not matching one of the patterns above — a plain function, a
private/package-private method, a class with no recognized annotation, a
CLI entry point framework not in the YAML list (e.g. `click`, `argparse`
subcommands), a message-queue consumer, a cron-triggered job, a gRPC
service method — is **never** assumed to be an entry point, and is
**never** assumed to be unreachable either. If such code's crypto call is
not otherwise reachable from something in the codebase, it lands on
`UNKNOWN` (see the classification rule above), not `INERT`. Extend
`rules/entrypoints.yaml` if a real codebase needs one of these patterns
recognized — do not special-case it in Python.

## Test-file detection

A finding is only eligible for `INERT` if every path to it runs exclusively
through test-file code (or it has no callers at all and sits directly in a
test file). "Test file" is a path/filename convention, not a directory
flag passed at scan time:

- **Python:** the path contains a `test` or `tests` directory segment, OR
  the filename starts with `test_` or ends with `_test.py`.
- **Java:** the path contains a `test` directory segment (matches
  Maven/Gradle-style `src/test/java/...` layouts), OR the filename ends
  with `Test.java` or `Tests.java`.
- **C/C++:** the path contains a `test` or `tests` directory segment, OR
  the filename starts with `test_` or ends with `_test.c`/`_test.cpp`/
  `_test.cc`/`_test.cxx` — mirroring the Python convention, the closest
  real-world equivalent this codebase already has (C has no single
  dominant test-framework layout convention the way pytest/JUnit have
  one).

## Why "not reachable + not test-confined" is UNKNOWN, not INERT

This is the crux of the fail-safe design. The call graph is a simple,
name-based, single-file-set analysis — it cannot see:

- reflection (`getattr(...)`, `Method.invoke`)
- dynamic dispatch through data structures (`dict[key]()`, a
  `Map<String, Runnable>`)
- calls from outside the scanned file set entirely (a separate service, a
  plugin loaded at runtime, an external caller of a public library API)
- unresolved imports

None of these make a function *provably* dead — they just make it
*unprovable* whether it's reachable. Treating "we found no caller" as proof
of death would silently misclassify exactly the kind of live code this tool
exists to catch. So the rule is: prove liveness (via a resolved path to an
entry point, or a resolved caller) to get `LIVE_*`; prove test-confinement
(every path runs through test code) to get `INERT`; otherwise, `UNKNOWN`.

`testdata/python/reachability_unknown_dynamic.py` and
`testdata/java/ReachabilityUnknownDynamic.java` are worked examples: a
crypto call sits in a helper referenced only through a dispatch
table/`Map`, invoked via a runtime key lookup the call-graph builder cannot
trace. It is production code, not test code, so — even though no resolved
caller was found — it classifies `UNKNOWN`, never `INERT`.

## Deep-nesting safety cap

`hash_patch/analyze/callgraph.py::_walk_py_calls` (and its C/C++ counterpart
`_walk_c_calls`) walks the tree-sitter AST of every function body to collect
its call sites. This walk uses an explicit heap-allocated stack, not
function-call recursion — a real-world file with deeply nested
expressions/definitions (confirmed on
`cryptography/hazmat/primitives/asymmetric/mldsa.py` from `pyca/cryptography`)
can exceed the native C thread stack before Python's own `RecursionError`
guard ever triggers, crashing the process with no catchable exception.
Moving to an explicit stack bounds traversal depth by available heap memory
instead.

As defense in depth against tree-sitter AST shapes deeper than any real file
should need, the walk also caps at `_MAX_WALK_DEPTH = 500`: a branch deeper
than that is simply not descended further. This does not change the module's
externally-visible fail-safe behavior — a call this cap prevents from being
seen becomes an unresolved/missing call edge, which already yields
`UNKNOWN` (never `INERT`) reachability per the rule above, exactly like any
other call this simple name-based resolver cannot see.

## Corpus

Four hand-authored scenarios per language, one per classification, live
under `testdata/python/` and `testdata/java/` (new files; the existing
`crypto_pyca.py` / `crypto_examples.java` golden fixtures are untouched).
`tests/golden/reachability_manifest.json` records the expected
classification for each, checked by
`tests/golden/test_reachability_corpus.py` and, per-scenario, by
`tests/unit/test_reachability.py`.
