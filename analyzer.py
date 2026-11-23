"""AST-based Python analyzer with conservative intra-function taint tracking."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


SOURCES = {
    "input", "builtins.input", "request.args", "request.form", "request.values",
    "request.json", "request.get_json", "sys.argv", "os.environ", "os.getenv",
}
SQL_METHODS = {"execute", "executemany", "execute_query", "executeupdate"}
SUBPROCESS_METHODS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call",
    "subprocess.check_output",
}
YAML_LOAD_METHODS = {"load", "load_all", "unsafe_load", "unsafe_load_all"}
YAML_UNSAFE_LOAD_METHODS = {"unsafe_load", "unsafe_load_all"}


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def line_text(source_lines: list[str], line: int) -> str:
    return source_lines[line - 1].strip() if 1 <= line <= len(source_lines) else ""


class Analyzer:
    def __init__(self, source: str, filename: str):
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.findings: list[dict[str, Any]] = []
        self._seen: set[tuple[int, str]] = set()

    def add(self, node: ast.AST, cwe: str, title: str, reason: str,
            confidence: float = 0.78, source_name: str = "static-analysis") -> None:
        line = getattr(node, "lineno", 1)
        key = (line, cwe)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "file": self.filename, "line": line, "cwe": cwe, "title": title,
            "evidence": line_text(self.lines, line), "reason": reason,
            "recommendation": "Review this data flow and use the safe pattern in the local reference.",
            "confidence": confidence, "source": source_name,
        })

    def is_source(self, node: ast.AST) -> bool:
        name = dotted_name(node)
        if name in SOURCES or name.startswith(("request.args.", "request.form.", "request.values.", "os.environ.")):
            return True
        if isinstance(node, ast.Call):
            called = dotted_name(node.func)
            return called in SOURCES or called.startswith(("request.args.", "request.form.", "request.values.", "os.environ."))
        if isinstance(node, ast.Subscript):
            return dotted_name(node.value) in {"sys.argv", "os.environ", "request.args", "request.form", "request.values"}
        if isinstance(node, ast.Attribute):
            return name in SOURCES or name.startswith(("request.args.", "request.form.", "request.values."))
        return False

    def tainted(self, node: ast.AST, names: set[str]) -> bool:
        if self.is_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in names
        if isinstance(node, ast.Attribute):
            return self.tainted(node.value, names) or self.is_source(node)
        if isinstance(node, ast.Subscript):
            return self.tainted(node.value, names) or self.is_source(node)
        if isinstance(node, ast.Call):
            return self.is_source(node) or any(self.tainted(a, names) for a in node.args) or any(
                self.tainted(k.value, names) for k in node.keywords)
        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr,
                             ast.List, ast.Tuple, ast.Set, ast.Dict, ast.UnaryOp)):
            return any(self.tainted(child, names) for child in ast.iter_child_nodes(node))
        return any(self.tainted(child, names) for child in ast.iter_child_nodes(node))

    @staticmethod
    def target_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            result: set[str] = set()
            for item in target.elts:
                result |= Analyzer.target_names(item)
            return result
        return set()

    def inspect_expr(self, node: ast.AST, names: set[str]) -> None:
        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            name = dotted_name(item.func)
            arg0 = item.args[0] if item.args else None
            arg_tainted = arg0 is not None and self.tainted(arg0, names)
            if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and arg_tainted:
                self.add(item, "CWE-95", "Untrusted data reaches dynamic code execution",
                         "Input from an external source can reach eval/exec.", 0.9)
            if name in SUBPROCESS_METHODS:
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                                 for k in item.keywords)
                if shell_true and arg_tainted:
                    self.add(item, "CWE-78", "Possible OS command injection",
                             "Untrusted data reaches a subprocess command executed through a shell.", 0.92)
            if name in {"os.system", "os.popen"} and arg_tainted:
                self.add(item, "CWE-78", "Possible OS command injection",
                         "Untrusted data reaches an OS shell command.", 0.9)
            if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"} and arg_tainted:
                self.add(item, "CWE-502", "Untrusted data is deserialized with pickle",
                         "Attacker-controlled bytes reach pickle deserialization.", 0.92)
            yaml_method = name.rsplit(".", 1)[-1]
            is_yaml_loader = name.split(".", 1)[0] in {"yaml", "ruamel"} and yaml_method in YAML_LOAD_METHODS
            if is_yaml_loader and arg_tainted:
                safe_loader_names = {"SafeLoader", "CSafeLoader"}
                safe = any(
                    keyword.arg == "Loader" and
                    dotted_name(keyword.value).rsplit(".", 1)[-1] in safe_loader_names
                    for keyword in item.keywords
                )
                explicit_unsafe = yaml_method in YAML_UNSAFE_LOAD_METHODS
                if explicit_unsafe or not safe:
                    title = ("Unsafe YAML deserialization" if explicit_unsafe else
                             "Possible unsafe YAML deserialization")
                    reason = ("Untrusted YAML is passed to an explicitly unsafe loader." if explicit_unsafe else
                              "Untrusted YAML is loaded without an explicit safe loader.")
                    self.add(item, "CWE-502", title, reason, 0.9 if explicit_unsafe else 0.86)
            method = name.rsplit(".", 1)[-1].lower()
            if method in SQL_METHODS and arg0 is not None and self.tainted(arg0, names):
                self.add(item, "CWE-89", "Possible SQL injection",
                         "Untrusted data reaches SQL execution as part of the query string.", 0.9)
            if name in {"open", "pathlib.Path"} and arg0 is not None and self.tainted(arg0, names):
                self.add(item, "CWE-22", "Untrusted data reaches a file path",
                         "An external value reaches a file path; verify it is constrained to an allowed directory.", 0.72)
            if name.endswith("render_template_string") and arg0 is not None and self.tainted(arg0, names):
                self.add(item, "CWE-1336", "Possible server-side template injection",
                         "Untrusted data is passed as a template string.", 0.9)
            if name in {"requests.get", "requests.post", "requests.put", "requests.delete", "httpx.get", "httpx.post"}:
                verify_disabled = any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False
                                      for k in item.keywords)
                if verify_disabled:
                    self.add(item, "CWE-295", "TLS certificate verification is disabled",
                             "The HTTP client is configured not to verify the remote certificate.", 0.78)
            if name == "ssl._create_unverified_context":
                self.add(item, "CWE-295", "TLS certificate verification is disabled",
                         "An SSL context is created without verifying the peer certificate.", 0.88)
            if name in {"tempfile.mktemp", "mktemp"}:
                self.add(item, "CWE-367", "Insecure temporary file name generation",
                         "mktemp() returns a path before creating the file, leaving a race window for another process.", 0.9)
            if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                self.add(item, "CWE-327", "Use of a potentially weak hash algorithm",
                         "MD5 and SHA-1 are unsuitable for security-sensitive collision resistance; assess the intended use.", 0.64)

            # Context-independent constructs that are dangerous even if the source
            # cannot be traced by this deliberately small analysis.
            if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
                self.add(item, "CWE-502", "Use of unsafe pickle deserialization",
                         "Pickle can execute attacker-controlled behavior when input is untrusted.", 0.72)

    def scan_block(self, statements: list[ast.stmt], incoming: set[str]) -> set[str]:
        names = set(incoming)
        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Function parameters are treated as potentially untrusted input.
                # This catches helper functions even without an interprocedural call graph.
                params = {arg.arg for arg in (stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs)}
                if stmt.args.vararg:
                    params.add(stmt.args.vararg.arg)
                if stmt.args.kwarg:
                    params.add(stmt.args.kwarg.arg)
                params -= {"self", "cls"}
                self.scan_block(stmt.body, params)
                continue
            if isinstance(stmt, ast.ClassDef):
                self.scan_block(stmt.body, set())
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = stmt.value
                self.inspect_expr(value, names)
                tainted = self.tainted(value, names)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    for identifier in self.target_names(target):
                        if tainted:
                            names.add(identifier)
                        else:
                            names.discard(identifier)
                continue
            if isinstance(stmt, ast.AugAssign):
                self.inspect_expr(stmt.value, names)
                if self.tainted(stmt.value, names):
                    names |= self.target_names(stmt.target)
                continue
            if isinstance(stmt, ast.If):
                self.inspect_expr(stmt.test, names)
                left = self.scan_block(stmt.body, set(names))
                right = self.scan_block(stmt.orelse, set(names))
                names |= left | right
                continue
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    self.inspect_expr(stmt.iter, names)
                    if self.tainted(stmt.iter, names):
                        names |= self.target_names(stmt.target)
                else:
                    self.inspect_expr(stmt.test, names)
                names |= self.scan_block(stmt.body, set(names))
                names |= self.scan_block(stmt.orelse, set(names))
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    self.inspect_expr(item.context_expr, names)
                    if item.optional_vars and self.tainted(item.context_expr, names):
                        names |= self.target_names(item.optional_vars)
                names |= self.scan_block(stmt.body, set(names))
                continue
            if isinstance(stmt, ast.Try):
                branches = [self.scan_block(stmt.body, set(names))]
                branches.extend(self.scan_block(h.body, set(names)) for h in stmt.handlers)
                branches.append(self.scan_block(stmt.orelse, set(names)))
                names |= set.union(*branches) if branches else set()
                names |= self.scan_block(stmt.finalbody, set(names))
                continue
            if isinstance(stmt, (ast.Expr, ast.Return, ast.Raise, ast.Assert)):
                value = getattr(stmt, "value", None) or getattr(stmt, "exc", None) or getattr(stmt, "test", None)
                if value is not None:
                    self.inspect_expr(value, names)
                continue
            # Catch calls in uncommon statement forms without changing taint state.
            self.inspect_expr(stmt, names)
        return names

    def run(self) -> list[dict[str, Any]]:
        try:
            tree = ast.parse(self.source, filename=self.filename)
        except SyntaxError as exc:
            line = exc.lineno or 1
            self.findings.append({
                "file": self.filename, "line": line, "cwe": "N/A",
                "title": "Python syntax error", "evidence": line_text(self.lines, line),
                "reason": f"Parsing stopped at line {line}: {exc.msg}",
                "recommendation": "Fix the syntax error and scan the file again.",
                "confidence": 1.0, "source": "static-analysis",
            })
            return self.findings
        self.scan_block(tree.body, set())
        self.scan_security_assignments(tree)
        self.scan_hardcoded_secrets(tree)
        return sorted(self.findings, key=lambda f: (f["line"], f["cwe"]))

    def scan_security_assignments(self, tree: ast.AST) -> None:
        """Catch explicit TLS verification disablement expressed as assignments."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            else:
                continue
            if value is None:
                continue
            target_names = {dotted_name(target).rsplit(".", 1)[-1] for target in targets}
            assigned_value = dotted_name(value)
            literal_false = isinstance(value, ast.Constant) and value.value is False
            if "verify_mode" in target_names and assigned_value.endswith("CERT_NONE"):
                self.add(node, "CWE-295", "TLS certificate verification is disabled",
                         "The SSL context is configured with CERT_NONE, so peer certificates are not verified.", 0.9)
            elif "check_hostname" in target_names and literal_false:
                self.add(node, "CWE-295", "TLS hostname verification is disabled",
                         "The SSL context is configured not to verify that the certificate matches the requested host.", 0.86)

    def scan_hardcoded_secrets(self, tree: ast.AST) -> None:
        import re
        for node in ast.walk(tree):
            targets: list[ast.AST] = []
            value: ast.AST | None = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            if value is None or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                continue
            if len(value.value) < 6:
                continue
            names = " ".join(dotted_name(t).lower() for t in targets)
            if re.search(r"(password|passwd|secret|api[_-]?key|access[_-]?token)", names):
                self.add(node, "CWE-798", "Possible hard-coded credential",
                         "A credential-like variable is assigned a string literal.", 0.8)


def analyze_file(path: Path) -> tuple[str, list[dict[str, Any]]]:
    if path.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"}:
        from .c_family import analyze_c_family
        return analyze_c_family(path)
    if path.suffix.lower() != ".py":
        raise ValueError(f"Unsupported source type: {path.suffix or '(no extension)'}")
    source = path.read_text(encoding="utf-8", errors="replace")
    return source, Analyzer(source, str(path)).run()
