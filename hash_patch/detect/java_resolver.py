"""hash_patch/detect/java_resolver.py — Multi-step argument resolver for Java crypto calls.

Implements the 5 resolution strategies for Java JCA/JCE call sites:
1. String literal (already implemented in tree-sitter extraction).
2. Static final field reference on a constants class in the same project
   (e.g. Cipher.getInstance(AlgorithmId.STORE_CIPHER)).
3. Map lookup pattern (e.g. CryptoPolicy.algorithmFor(profile) backed by
   map.put calls in constructors with literal or static-field-resolvable values).
4. Parameter passthrough (e.g. SignerFactory.create(requested) tracing backward
   to callers across the project, capped at 3 hops).
5. Ternary / if-else branching (e.g. cond ? ALGO_A : ALGO_B) resolving each
   branch independently and emitting one finding per branch tagged with
   branch_condition.
6. Interface-based dispatch (e.g. `AlgorithmProvider provider = ...;
   Cipher.getInstance(provider.algorithmFor(kind))` where `provider`'s
   STATIC type is an interface): resolved by finding EVERY class in the
   project that `implements` that interface, resolving the algorithm from
   EACH implementation's override of the called method independently —
   never picking one arbitrarily, same fail-safe "keep every candidate"
   rule Strategy 5's branch handling already follows. Genuinely dynamic
   dispatch that cannot be resolved statically at all (a concrete
   implementation chosen via `Class.forName(...)` from a runtime-read
   class name, reflection, a service loader) is explicitly NOT this
   strategy's job and stays unresolved — see
   hash_patch/detect/java.py::JavaJcaDetector and
   testdata/java/interface_dispatch/RuntimeDynamicDispatch.java's own
   corpus fixture for that boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tree_sitter_java as _ts_java
    from tree_sitter import Language, Parser

    _LANG = Language(_ts_java.language())
    _PARSER = Parser(_LANG)
except Exception:
    _LANG = None
    _PARSER = None


@dataclass
class JavaResolution:
    """Represents one resolved or unresolved candidate for a crypto API argument."""

    algo_raw: str | None
    confidence: str  # "HIGH" or "LOW"
    resolution_path: list[str] | None = None
    branch_condition: str | None = None
    algo_node: Any | None = None
    # The file `algo_node` was parsed from. Parameter passthrough (Strategy 4)
    # is the only strategy that crosses into a different physical file than
    # the one resolution started from — every other strategy's algo_node
    # belongs to whatever file resolve_node() was called with. A caller must
    # never combine `algo_node`'s tree-sitter position with a `locator` for a
    # different file (that produces an internally inconsistent Evidence: a
    # line number that is only valid in a different file's coordinate
    # space) — see hash_patch/detect/java.py's use of this field.
    algo_file: Path | None = None


def extract_string_fragment(node: Any | None) -> str | None:
    """Return inner string text from tree-sitter string_literal node, or None."""
    if node is None:
        return None
    if node.type == "string_literal":
        for child in node.children:
            if child.type == "string_fragment":
                return child.text.decode("utf-8", errors="replace")
    return None


def find_project_root(target: Path) -> Path:
    """Locate the innermost Java project root containing build markers or src."""
    target = target.resolve()
    cur = target.parent
    while cur != cur.parent:
        if (
            (cur / "pom.xml").exists()
            or (cur / "build.gradle").exists()
            or (cur / "settings.gradle").exists()
            or (cur / "src").is_dir()
        ):
            return cur
        cur = cur.parent
    return target.parent


class JavaProjectIndex:
    """Indexes Java source files and provides resolution for classes, fields, maps, and callers."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files_by_name: dict[str, list[Path]] = {}
        for p in root.rglob("*.java"):
            self.files_by_name.setdefault(p.name, []).append(p)
        self.trees: dict[Path, Any] = {}

    def get_tree(self, path: Path) -> Any | None:
        if not path.is_file():
            return None
        if path not in self.trees:
            if _PARSER is None:
                return None
            self.trees[path] = _PARSER.parse(path.read_bytes())
        return self.trees[path]

    def find_class_file(self, class_name: str, current_file: Path) -> Path | None:
        """Locate the .java file corresponding to class_name."""
        # 1. Same package / same directory
        same_dir = current_file.parent / f"{class_name}.java"
        if same_dir.is_file():
            return same_dir

        # 2. Match via import statements in current_file
        tree = self.get_tree(current_file)
        if tree is not None:
            for child in tree.root_node.children:
                if child.type == "import_declaration":
                    text = child.text.decode("utf-8", errors="replace").strip()
                    if text.endswith(f".{class_name};"):
                        cands = self.files_by_name.get(f"{class_name}.java", [])
                        if cands:
                            return cands[0]
                    elif text.endswith(".*;"):
                        pkg = text.replace("import ", "").replace(".*;", "").strip()
                        pkg_path = Path(*pkg.split(".")) / f"{class_name}.java"
                        for cand in self.files_by_name.get(f"{class_name}.java", []):
                            if str(cand).replace("\\", "/").endswith(str(pkg_path).replace("\\", "/")):
                                return cand

        # 3. Unambiguous match in project
        cands = self.files_by_name.get(f"{class_name}.java", [])
        if len(cands) == 1:
            return cands[0]

        return None

    def get_class_constants(self, class_file: Path) -> dict[str, tuple[str, list[str]]]:
        """Parse static final field declarations in class_file."""
        tree = self.get_tree(class_file)
        if tree is None:
            return {}
        constants: dict[str, tuple[str, list[str]]] = {}
        class_name = class_file.stem

        def walk(node: Any) -> None:
            if node.type == "field_declaration":
                for c in node.children:
                    if c.type == "variable_declarator":
                        n = c.child_by_field_name("name")
                        v = c.child_by_field_name("value")
                        if n and v:
                            name_str = n.text.decode("utf-8", errors="replace")
                            val_str = extract_string_fragment(v)
                            if val_str is not None:
                                path_step = f'{class_name}.{name_str} -> "{val_str}"'
                                constants[name_str] = (val_str, [path_step])
            for c in node.children:
                walk(c)

        walk(tree.root_node)
        return constants

    def resolve_field_access(self, node: Any, current_file: Path) -> tuple[str | None, list[str]]:
        """Resolve a ClassName.FIELD field_access node to its literal value."""
        obj_node = node.child_by_field_name("object")
        field_node = node.child_by_field_name("field")
        if not obj_node or not field_node:
            return None, []
        class_name = obj_node.text.decode("utf-8", errors="replace")
        field_name = field_node.text.decode("utf-8", errors="replace")
        class_file = self.find_class_file(class_name, current_file)
        if not class_file:
            return None, []
        constants = self.get_class_constants(class_file)
        if field_name in constants:
            val, path = constants[field_name]
            return val, path
        return None, []

    def get_enclosing_method(self, node: Any) -> Any | None:
        cur = node
        while cur:
            if cur.type in ("method_declaration", "constructor_declaration"):
                return cur
            cur = cur.parent
        return None

    def get_local_variable_declaration(self, var_name: str, method_node: Any) -> Any | None:
        res = None

        def walk(n: Any) -> None:
            nonlocal res
            if res is not None:
                return
            if n.type == "variable_declarator":
                nm = n.child_by_field_name("name")
                if nm and nm.text.decode("utf-8", errors="replace") == var_name:
                    res = n.child_by_field_name("value")
                    return
            for c in n.children:
                walk(c)

        if method_node:
            walk(method_node)
        return res

    def get_field_type_in_class(self, field_name: str, class_node: Any) -> str | None:
        def walk(n: Any) -> str | None:
            if n.type == "field_declaration":
                for sub in n.children:
                    if sub.type == "variable_declarator":
                        nm = sub.child_by_field_name("name")
                        if nm and nm.text.decode("utf-8", errors="replace") == field_name:
                            for typ in n.children:
                                if typ.type in ("type_identifier", "generic_type"):
                                    return typ.text.decode("utf-8", errors="replace").split("<")[0]
            for c in n.children:
                r = walk(c)
                if r:
                    return r
            return None

        return walk(class_node)

    def find_implementing_classes(self, interface_name: str) -> list[tuple[Any, Path]]:
        """Every (class_declaration node, file) in the project whose
        `implements` clause names `interface_name` — see Strategy 6 in this
        module's docstring. Project-wide (not scoped to one file), since an
        interface's implementations routinely live in different files than
        both the interface declaration and the call site.
        """
        results: list[tuple[Any, Path]] = []
        for path in self.root.rglob("*.java"):
            tree = self.get_tree(path)
            if tree is None:
                continue
            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type == "class_declaration":
                    interfaces_node = n.child_by_field_name("interfaces")
                    if interfaces_node is not None:
                        text = interfaces_node.text.decode("utf-8", errors="replace")
                        if re.search(rf"\b{re.escape(interface_name)}\b", text):
                            results.append((n, path))
                stack.extend(n.children)
        return results

    @staticmethod
    def find_method_in_class(class_node: Any, method_name: str) -> Any | None:
        for c in class_node.children:
            if c.type != "class_body":
                continue
            for m in c.children:
                if m.type == "method_declaration":
                    name_node = m.child_by_field_name("name")
                    if name_node is not None and name_node.text.decode("utf-8", errors="replace") == method_name:
                        return m
        return None

    def _local_variable_declared_type(self, var_name: str, method_node: Any) -> str | None:
        """The declared TYPE of a local variable (unlike
        `get_local_variable_declaration`, which returns its VALUE node) —
        needed to detect an interface-typed local for Strategy 6.
        """
        res: str | None = None

        def walk(n: Any) -> None:
            nonlocal res
            if res is not None:
                return
            if n.type == "local_variable_declaration":
                for sub in n.children:
                    if sub.type == "variable_declarator":
                        nm = sub.child_by_field_name("name")
                        if nm is not None and nm.text.decode("utf-8", errors="replace") == var_name:
                            for typ in n.children:
                                if typ.type in ("type_identifier", "generic_type"):
                                    res = typ.text.decode("utf-8", errors="replace").split("<")[0]
                                    return
            for c in n.children:
                walk(c)

        if method_node is not None:
            walk(method_node)
        return res

    def _declared_type_of_object(self, obj_node: Any, inv_node: Any, current_file: Path) -> str | None:
        """Best-effort declared TYPE of a method_invocation's `object` node
        -- a parameter type, a local variable's declared type, or a field
        type in the enclosing class. Used to detect a call through an
        INTERFACE-typed reference (Strategy 6) before assuming Strategy 3's
        map-lookup shape.
        """
        if obj_node is None or obj_node.type != "identifier":
            return None
        var_name = obj_node.text.decode("utf-8", errors="replace")
        enclosing_method = self.get_enclosing_method(inv_node)
        if enclosing_method is not None:
            params = enclosing_method.child_by_field_name("parameters")
            if params is not None:
                for p in params.named_children:
                    if p.type == "formal_parameter":
                        nm = p.child_by_field_name("name")
                        if nm is not None and nm.text.decode("utf-8", errors="replace") == var_name:
                            type_node = p.child_by_field_name("type")
                            if type_node is not None:
                                return type_node.text.decode("utf-8", errors="replace").split("<")[0]
            decl_type = self._local_variable_declared_type(var_name, enclosing_method)
            if decl_type is not None:
                return decl_type
        cur = inv_node
        while cur is not None and cur.type != "class_declaration":
            cur = cur.parent
        if cur is not None:
            return self.get_field_type_in_class(var_name, cur)
        return None

    _JCA_GETINSTANCE_METHOD = "getInstance"

    @staticmethod
    def _return_expressions_in(method_node: Any) -> list[Any]:
        """Every `return <expr>;`'s expression node directly inside
        `method_node` (not descending into a nested lambda/anonymous class,
        which would have its own separate return flow).
        """
        exprs: list[Any] = []
        stack = [method_node]
        while stack:
            n = stack.pop()
            for c in n.children:
                if c.type in ("lambda_expression", "class_declaration"):
                    continue  # separate return flow -- do not descend
                if c.type == "return_statement":
                    for sub in c.children:
                        if sub.is_named:
                            exprs.append(sub)
                            break
                    continue
                stack.append(c)
        return exprs

    def resolve_interface_dispatch(
        self, interface_name: str, method_name: str, inv_node: Any, depth: int = 0
    ) -> list[JavaResolution] | None:
        """Strategy 6: a call through a variable/parameter/field whose
        STATIC type is a Java interface, resolved by finding every class in
        the project that `implements` it and resolving the algorithm EACH
        implementation's override of `method_name` returns, independently.

        Two shapes are handled, mirroring how a real algorithm-selection
        method is written: (a) the override directly `return`s a
        resolvable expression (a string literal, a static field, ...) —
        the common "algorithm factory" shape; (b) the override itself makes
        a nested `<Class>.getInstance(...)` JCA call whose own argument is
        resolvable — a provider that performs the JCA lookup itself rather
        than just naming an algorithm.

        Returns None (never an empty list) when `interface_name` has no
        implementing classes found in the project at all, so the caller can
        fall back to its other strategies rather than conflating "not an
        interface with implementers" with "found none" — an empty list
        would incorrectly look identical to "resolved, but no candidates
        matched", which is a real (different) case Strategy 5 already uses
        empty-list-vs-None for elsewhere in this file.
        """
        implementers = self.find_implementing_classes(interface_name)
        if not implementers:
            return None

        results: list[JavaResolution] = []
        for class_node, class_file in implementers:
            method_node = self.find_method_in_class(class_node, method_name)
            if method_node is None:
                continue
            class_name_node = class_node.child_by_field_name("name")
            class_name = (
                class_name_node.text.decode("utf-8", errors="replace") if class_name_node is not None else "?"
            )

            candidates: list[tuple[Any, str]] = [
                (expr, f"{class_name}.{method_name} returns") for expr in self._return_expressions_in(method_node)
            ]
            for call in self._nested_getinstance_calls_in(method_node):
                args_node = call.child_by_field_name("arguments")
                first_arg = next(iter(args_node.named_children), None) if args_node is not None else None
                if first_arg is not None:
                    call_receiver = call.child_by_field_name("object")
                    receiver_text = (
                        call_receiver.text.decode("utf-8", errors="replace") if call_receiver is not None else "?"
                    )
                    candidates.append((first_arg, f"{class_name}.{method_name} -> {receiver_text}.getInstance"))

            for expr, label in candidates:
                for res in self.resolve_node(expr, class_file, depth=depth + 1):
                    if res.algo_raw is None:
                        continue
                    res.resolution_path = [label] + (res.resolution_path or [])
                    res.algo_node = expr
                    res.algo_file = class_file
                    results.append(res)
        return results or None

    def _nested_getinstance_calls_in(self, node: Any) -> list[Any]:
        """Every `<Class>.getInstance(...)`-shaped method_invocation node
        inside `node` — the common shape every JCA/JCE algorithm-selection
        call in rules/java_jca.yaml uses (Cipher/Signature/MessageDigest/
        KeyPairGenerator/Mac/KeyAgreement/KeyFactory.getInstance(...)).
        """
        calls: list[Any] = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                name_node = n.child_by_field_name("name")
                if name_node is not None and name_node.text.decode("utf-8", errors="replace") == self._JCA_GETINSTANCE_METHOD:
                    calls.append(n)
            stack.extend(n.children)
        return calls

    def resolve_map_lookup(self, inv_node: Any, current_file: Path, depth: int = 0) -> list[JavaResolution]:
        """Strategy 3: Resolve map lookup method calls (e.g. policy.algorithmFor(profile))."""
        obj_node = inv_node.child_by_field_name("object")
        name_node = inv_node.child_by_field_name("name")
        args_node = inv_node.child_by_field_name("arguments")
        if not name_node or not args_node:
            return []
        method_name = name_node.text.decode("utf-8", errors="replace")
        args = list(args_node.named_children)
        arg0 = args[0] if args else None

        class_file = None
        class_name = None
        if obj_node:
            if obj_node.type == "object_creation_expression":
                for c in obj_node.children:
                    if c.type in ("type_identifier", "generic_type"):
                        class_name = c.text.decode("utf-8", errors="replace").split("<")[0]
                        break
            elif obj_node.type == "identifier":
                var_name = obj_node.text.decode("utf-8", errors="replace")
                enclosing_method = self.get_enclosing_method(inv_node)
                decl_val = self.get_local_variable_declaration(var_name, enclosing_method)
                if decl_val and decl_val.type == "object_creation_expression":
                    for c in decl_val.children:
                        if c.type in ("type_identifier", "generic_type"):
                            class_name = c.text.decode("utf-8", errors="replace").split("<")[0]
                            break
                else:
                    cur = inv_node
                    while cur and cur.type != "class_declaration":
                        cur = cur.parent
                    if cur:
                        class_name = self.get_field_type_in_class(var_name, cur)

        if not class_name and obj_node and obj_node.type == "identifier":
            class_name = obj_node.text.decode("utf-8", errors="replace")

        if class_name:
            class_file = self.find_class_file(class_name, current_file)

        if not class_file and not obj_node:
            class_file = current_file

        if not class_file:
            return []

        tree = self.get_tree(class_file)
        if tree is None:
            return []

        # Find all .put calls on maps in class_file constructors/methods
        map_table: dict[str, tuple[str, list[str]]] = {}

        def walk_puts(n: Any) -> None:
            if n.type == "method_invocation":
                nm = n.child_by_field_name("name")
                ag = n.child_by_field_name("arguments")
                if nm and nm.text == b"put" and ag:
                    put_args = list(ag.named_children)
                    if len(put_args) >= 2:
                        k_str = extract_string_fragment(put_args[0])
                        v_arg = put_args[1]
                        if k_str:
                            if v_arg.type == "field_access":
                                v_val, v_path = self.resolve_field_access(v_arg, class_file)
                                if v_val:
                                    map_table[k_str] = (v_val, v_path)
                            elif v_arg.type == "string_literal":
                                s = extract_string_fragment(v_arg)
                                if s:
                                    map_table[k_str] = (s, [])
            for c in n.children:
                walk_puts(c)

        walk_puts(tree.root_node)

        if arg0 is not None:
            resolved_keys = self.resolve_node(arg0, current_file, depth=depth + 1)
            results = []
            for rk in resolved_keys:
                if rk.algo_raw and rk.algo_raw in map_table:
                    val, path = map_table[rk.algo_raw]
                    rec_label = obj_node.text.decode("utf-8", errors="replace") if obj_node else class_name
                    rec_call = f'{rec_label}.{method_name}("{rk.algo_raw}")'
                    full_path = [f"{rec_call} -> {path[0] if path else val}"] + (
                        path[1:] if len(path) > 1 else path
                    )
                    results.append(
                        JavaResolution(
                            algo_raw=val,
                            confidence="HIGH",
                            resolution_path=full_path,
                            algo_node=inv_node,
                            algo_file=current_file,
                        )
                    )
            if results:
                return results
        return []

    def resolve_parameter_passthrough(
        self, param_name: str, method_node: Any, current_file: Path, depth: int = 0
    ) -> list[JavaResolution]:
        """Strategy 4: Trace parameter passthrough backward to callers across the project."""
        if depth > 3:
            return [
                JavaResolution(
                    algo_raw=None,
                    confidence="LOW",
                    resolution_path=[f"depth limit exceeded tracing {param_name}"],
                )
            ]

        params_node = method_node.child_by_field_name("parameters")
        if not params_node:
            return []
        param_idx = -1
        idx = 0
        for p in params_node.named_children:
            if p.type == "formal_parameter":
                nm = p.child_by_field_name("name")
                if nm and nm.text.decode("utf-8", errors="replace") == param_name:
                    param_idx = idx
                    break
                idx += 1
        if param_idx == -1:
            return []

        method_name = method_node.child_by_field_name("name").text.decode("utf-8", errors="replace")
        cur = method_node
        while cur and cur.type != "class_declaration":
            cur = cur.parent
        class_name = cur.child_by_field_name("name").text.decode("utf-8", errors="replace") if cur else ""

        results: list[JavaResolution] = []
        for file_path in self.root.rglob("*.java"):
            content = file_path.read_bytes()
            if method_name.encode() not in content:
                continue
            tree = self.get_tree(file_path)
            if tree is None:
                continue

            def walk_calls(n: Any) -> None:
                if n.type == "method_invocation":
                    nm = n.child_by_field_name("name")
                    ag = n.child_by_field_name("arguments")
                    if nm and nm.text.decode("utf-8", errors="replace") == method_name and ag:
                        args = list(ag.named_children)
                        if len(args) > param_idx:
                            obj = n.child_by_field_name("object")
                            match = False
                            if not obj or obj.text.decode("utf-8", errors="replace") == class_name:
                                match = True
                            else:
                                cur_enc = self.get_enclosing_method(n)
                                decl_val = self.get_local_variable_declaration(
                                    obj.text.decode("utf-8", errors="replace"), cur_enc
                                )
                                if decl_val and class_name in decl_val.text.decode("utf-8", errors="replace"):
                                    match = True
                                else:
                                    c_node = n
                                    while c_node and c_node.type != "class_declaration":
                                        c_node = c_node.parent
                                    if (
                                        c_node
                                        and self.get_field_type_in_class(
                                            obj.text.decode("utf-8", errors="replace"), c_node
                                        )
                                        == class_name
                                    ):
                                        match = True
                            if match:
                                caller_arg = args[param_idx]
                                caller_res = self.resolve_node(caller_arg, file_path, depth=depth + 1)
                                for cr in caller_res:
                                    step = (
                                        f"{class_name}.{method_name}({param_name}) <- "
                                        f"{n.text.decode('utf-8', errors='replace')}"
                                    )
                                    p = [step] + (cr.resolution_path or [])
                                    # Preserve the deepest resolution's own
                                    # algo_node/algo_file (e.g. the literal
                                    # "customer-auth" argument several hops
                                    # further up the call chain) rather than
                                    # clobbering it with this hop's call
                                    # node — otherwise every branch collapses
                                    # onto the SAME position (this hop's
                                    # call site) and, worse, that position
                                    # would later be paired with a
                                    # `locator` for a different file
                                    # entirely by the caller.
                                    results.append(
                                        JavaResolution(
                                            algo_raw=cr.algo_raw,
                                            confidence=cr.confidence,
                                            resolution_path=p,
                                            branch_condition=cr.branch_condition,
                                            algo_node=cr.algo_node if cr.algo_node is not None else n,
                                            algo_file=cr.algo_file if cr.algo_file is not None else file_path,
                                        )
                                    )
                for c in n.children:
                    walk_calls(c)

            walk_calls(tree.root_node)
        if not results:
            return [
                JavaResolution(
                    algo_raw=None,
                    confidence="LOW",
                    resolution_path=None,
                    algo_node=None,
                )
            ]
        return results

    def resolve_node(self, node: Any, current_file: Path, depth: int = 0) -> list[JavaResolution]:
        """Recursively resolves an argument expression node to its possible concrete values."""
        if node is None or depth > 5:
            return [JavaResolution(algo_raw=None, confidence="LOW")]

        # Strategy 1: String literal
        s = extract_string_fragment(node)
        if s is not None:
            return [
                JavaResolution(
                    algo_raw=s, confidence="HIGH", resolution_path=None, algo_node=node, algo_file=current_file
                )
            ]

        # Strategy 2: Field access (e.g. AlgorithmId.STORE_CIPHER) — `node`
        # is the reference site (e.g. in the calling file), never the
        # constants class's own declaration file, regardless of where
        # resolve_field_access had to look to find the value.
        if node.type == "field_access":
            val, path = self.resolve_field_access(node, current_file)
            if val:
                return [
                    JavaResolution(
                        algo_raw=val,
                        confidence="HIGH",
                        resolution_path=path,
                        algo_node=node,
                        algo_file=current_file,
                    )
                ]

        # Strategy 5: Ternary expression (cond ? A : B)
        if node.type == "ternary_expression":
            cond = node.child_by_field_name("condition")
            conseq = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            cond_text = cond.text.decode("utf-8", errors="replace") if cond else "cond"
            res: list[JavaResolution] = []
            if conseq:
                for r in self.resolve_node(conseq, current_file, depth=depth):
                    r.branch_condition = f"{cond_text} == true"
                    res.append(r)
            if alt:
                for r in self.resolve_node(alt, current_file, depth=depth):
                    r.branch_condition = f"{cond_text} == false"
                    res.append(r)
            return res

        # Strategy 3: Method invocation (e.g. new CryptoPolicy().algorithmFor(profile))
        # Strategy 6 is tried FIRST: if the invocation's receiver is
        # statically typed as an interface with real implementing classes
        # in the project, this is interface dispatch, not the map-lookup
        # shape Strategy 3 assumes -- resolve_map_lookup would otherwise
        # treat the interface's own (bodyless) declaration file as
        # "class_file" and correctly, but uninformatively, find nothing.
        if node.type == "method_invocation":
            obj_node = node.child_by_field_name("object")
            name_node = node.child_by_field_name("name")
            if obj_node is not None and name_node is not None:
                receiver_type = self._declared_type_of_object(obj_node, node, current_file)
                if receiver_type is not None:
                    method_name = name_node.text.decode("utf-8", errors="replace")
                    interface_results = self.resolve_interface_dispatch(
                        receiver_type, method_name, node, depth=depth
                    )
                    if interface_results is not None:
                        return interface_results
            return self.resolve_map_lookup(node, current_file, depth=depth)

        # Identifier: local variable, method parameter, or class constant
        if node.type == "identifier":
            var_name = node.text.decode("utf-8", errors="replace")
            enclosing_method = self.get_enclosing_method(node)

            # Check local variable declarations
            decl_val = self.get_local_variable_declaration(var_name, enclosing_method)
            if decl_val is not None:
                return self.resolve_node(decl_val, current_file, depth=depth)

            # Strategy 4: Check if identifier is a method parameter
            if enclosing_method:
                params = enclosing_method.child_by_field_name("parameters")
                if params:
                    for p in params.named_children:
                        if p.type == "formal_parameter":
                            nm = p.child_by_field_name("name")
                            if nm and nm.text.decode("utf-8", errors="replace") == var_name:
                                return self.resolve_parameter_passthrough(
                                    var_name, enclosing_method, current_file, depth=depth
                                )

            # Check static constants in current class
            cur_class = node
            while cur_class and cur_class.type != "class_declaration":
                cur_class = cur_class.parent
            if cur_class:
                constants = self.get_class_constants(current_file)
                if var_name in constants:
                    val, path = constants[var_name]
                    return [
                        JavaResolution(
                            algo_raw=val,
                            confidence="HIGH",
                            resolution_path=path,
                            algo_node=node,
                            algo_file=current_file,
                        )
                    ]

        return [JavaResolution(algo_raw=None, confidence="LOW", algo_node=node, algo_file=current_file)]


_PROJECT_INDEX_CACHE: dict[Path, JavaProjectIndex] = {}


def get_project_index(target: Path) -> JavaProjectIndex:
    """Return a cached JavaProjectIndex for the target's project root."""
    root = find_project_root(target)
    if root not in _PROJECT_INDEX_CACHE:
        _PROJECT_INDEX_CACHE[root] = JavaProjectIndex(root)
    return _PROJECT_INDEX_CACHE[root]


def resolve_java_argument(arg_node: Any, current_file: Path) -> list[JavaResolution]:
    """Top-level resolver function for a Java crypto API argument node."""
    index = get_project_index(current_file)
    return index.resolve_node(arg_node, current_file)
