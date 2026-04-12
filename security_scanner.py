import argparse
import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


IGNORED_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "security",
    "security_scanner.py",
    "app",
    ".gitignore"
}

CONFIG_SUFFIXES = {".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".json"}
CONFIG_FILENAMES = {".env", "docker-compose.yml", "docker-compose.yaml"}
PASSWORD_NAMES = {"password", "passwd", "pwd"}
SECRET_NAMES = {"secret", "api_key", "apikey", "token", "access_key", "private_key"}
WEAK_HASHES = {"md5", "sha1"}
SAFE_YAML_LOADERS = {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"}
SQL_KEYWORDS = {"select", "insert", "update", "delete", "from", "where", "values"}
LDAP_HINTS = {"(&(", "(|(", "(uid=", "(cn=", "(mail=", "objectclass"}
HTML_HINTS = ("<script", "<h1", "<div", "<span", "<img", "<a", "<p", "</")
REQUEST_SOURCES = {
    "request.args",
    "request.form",
    "request.values",
    "request.headers",
    "request.cookies",
    "request.json",
    "request.files",
}
SSRF_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.request",
    "requests.Session.get",
    "requests.Session.post",
    "requests.Session.put",
    "requests.Session.patch",
    "requests.Session.delete",
    "requests.Session.head",
    "urllib.request.urlopen",
}
COMMAND_SINKS = {"os.system", "os.popen"}
SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.getoutput",
}
FILE_SINKS = {"open", "builtins.open", "pathlib.Path.open"}
LDAP_SINKS = {"search", "search_s"}
UNSUPPORTED_CATEGORIES = [
    "Broken Access Control",
    "Insecure Design",
    "Vulnerable & Outdated Components",
    "Identification & Authentication Failures",
    "Security Logging & Monitoring Failures",
]

# Severity levels.
# SQL injection has two severities depending on context:
#   "SQL injection"        → build-site only (string concat / f-string)  → MEDIUM
#   "SQL injection (sink)" → confirmed to reach execute()                → HIGH
# The sink variant is normalised back to "SQL injection" in the output.
SEVERITY_MAP = {
    "SQL injection": "MEDIUM",
    "SQL injection (sink)": "HIGH",
    "OS command injection": "HIGH",
    "LDAP injection": "HIGH",
    "Cross-site scripting (XSS)": "MEDIUM",
    "Server-Side Request Forgery (SSRF)": "MEDIUM",
    "User-controlled URL request": "MEDIUM",
    "User-controlled file path": "MEDIUM",
    "Path Traversal (High Severity)": "HIGH",
    "Path Traversal": "MEDIUM",
    "Server-Side Request Forgery (SSRF) - Internal": "HIGH",
    "Unsafe deserialization": "HIGH",
    "Dynamic code execution": "HIGH",
    "Weak hash": "LOW",
    "Plaintext password": "LOW",
    "Hardcoded secret": "LOW",
    "Unsafe YAML load": "MEDIUM",
    "Debug mode enabled": "LOW",
    "Exposed service binding": "LOW",
    "Debug mode enabled in config": "LOW",
    "Service listens on 0.0.0.0": "LOW",
}

DEBUG_PATTERNS = [
    (
        re.compile(r"^\s*(debug|flask_debug)\s*[:=]\s*(true|1)\s*$", re.IGNORECASE),
        "Debug mode enabled in config",
        "Disable debug mode outside local development.",
    ),
    (
        re.compile(r"^\s*(host|bind)\s*[:=]\s*['\"]?0\.0\.0\.0['\"]?\s*$", re.IGNORECASE),
        "Service listens on 0.0.0.0",
        "Bind only to required interfaces and protect the service with network controls.",
    ),
]

ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
SIMPLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRING_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([\"']).*?\2\s*$")
FSTRING_PREFIX_RE = re.compile(r"(?i)(?:^|[^A-Za-z0-9_])(?:[rub]{0,2}f|f[rub]{0,2})['\"]")

STRING_INJECTION_MESSAGES = {
    "SQL injection": {
        "string concatenation": "Untrusted input is concatenated into a SQL string.",
        "f-string": "Untrusted input is embedded into a SQL f-string.",
        "format string": "Untrusted input is interpolated into a SQL format string.",
    },
    "LDAP injection": {
        "string concatenation": "Untrusted input is concatenated into an LDAP filter.",
        "f-string": "Untrusted input is embedded into an LDAP f-string.",
        "format string": "Untrusted input is interpolated into an LDAP format string.",
    },
    "Cross-site scripting (XSS)": {
        "string concatenation": "Untrusted input is combined into an HTML string.",
        "f-string": "Untrusted input is embedded into an HTML f-string.",
        "format string": "Untrusted input is interpolated into an HTML format string.",
    },
}

STRING_INJECTION_FIXES = {
    "SQL injection": "Use parameterized queries instead of string concatenation or interpolation.",
    "LDAP injection": "Use safe LDAP filter builders or escape user input before building filters.",
    "Cross-site scripting (XSS)": "Escape untrusted output or use auto-escaping templates.",
}


def get_severity(issue: str) -> str:
    return SEVERITY_MAP.get(issue, "LOW")


@dataclass
class Finding:
    path: Path
    lines: list
    category: str
    issue: str
    message: str
    fix: str
    severity: str = "LOW"
    origin: str = None
    # Flow chain from taint source to sink, e.g. ["user_id", "query", "result"]
    flow: list = field(default_factory=list)


def finding_identity(finding: Finding):
    normalised_issue = finding.issue.replace(" (sink)", "")
    return finding.path, tuple(finding.lines), finding.category, normalised_issue


def sort_findings(findings):
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(
        findings,
        key=lambda f: (
            severity_order.get(f.severity, 9),
            f.origin or "",
            str(f.path),
            f.lines[0] if f.lines else 9999,
            f.category,
            f.issue,
        ),
    )


def dedupe_findings(findings):
    """Two-stage deduplication.

    Stage 1 – per-line severity collapse:
      Findings sharing the same (path, line, category, normalised_issue) are
      collapsed to the single highest-severity representative.

    Stage 2 – cross-line sink suppression:
      After stage 1, if a HIGH finding exists for a (path, category, issue)
      combination, all MEDIUM findings for the same combination are dropped.
    """
    specific_issues = {
        "SQL injection",
        "OS command injection",
        "LDAP injection",
        "Cross-site scripting (XSS)",
        "User-controlled file path",
        "User-controlled URL request",
    }

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    # ── Stage 1: per-line severity collapse ──────────────────────────────────
    best: dict = {}
    for finding in findings:
        identity = finding_identity(finding)
        existing = best.get(identity)
        if existing is None:
            best[identity] = finding
        else:
            if severity_order.get(finding.severity, 9) < severity_order.get(existing.severity, 9):
                best[identity] = finding

    stage1 = list(best.values())

    # ── Stage 2: cross-line MEDIUM suppression when HIGH exists ──────────────
    high_keys: set = set()
    for f in stage1:
        if f.severity == "HIGH":
            high_keys.add((f.path, f.category, f.issue.replace(" (sink)", "")))

    stage2 = [
        f for f in stage1
        if not (
            f.severity == "MEDIUM"
            and (f.path, f.category, f.issue.replace(" (sink)", "")) in high_keys
        )
    ]

    return sort_findings(stage2)


def iter_targets(target: Path):
    if target.is_file():
        yield target
        return

    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix == ".py" or is_config_file(path):
            yield path


def is_config_file(path: Path):
    return path.suffix.lower() in CONFIG_SUFFIXES or path.name.lower() in CONFIG_FILENAMES


def short_path(path: Path):
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def get_full_name(node, imports):
    if isinstance(node, ast.Name):
        return imports.get(node.id, node.id)

    if isinstance(node, ast.Attribute):
        base = get_full_name(node.value, imports)
        if base:
            return f"{base}.{node.attr}"
        return node.attr

    return ""


def name_matches(full_name, candidates):
    if not full_name:
        return False

    return full_name in candidates or any(full_name.endswith(f".{candidate}") for candidate in candidates)


def iter_target_names(node):
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from iter_target_names(item)


def lowered_literals(node):
    values = []

    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            values.append(child.value.lower())

    return values


def contains_keyword_text(text, keywords):
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def get_text_string_style(text):
    if FSTRING_PREFIX_RE.search(text):
        return "f-string"
    if ".format(" in text:
        return "format string"
    if "+" in text:
        return "string concatenation"
    return None


class PythonSecurityScanner:
    def __init__(self, path: Path, code: str):
        self.path = path
        self.code = code
        self.tree = ast.parse(code, filename=str(path))
        self.findings = []
        self.imports = self.collect_imports()
        self.tainted_names: set = set()
        self.seen: set = set()
        self.tainted_return_funcs: set = set()
        # Maps each tainted variable back to its ultimate taint origin variable.
        self.var_origin: dict = {}
        # [NEW] Maps each tainted variable to its immediate predecessor in the
        # taint chain, enabling full flow reconstruction: a → b → c → sink.
        self.var_parent: dict = {}
        self._reported_taint_issues: set = set()

    def collect_imports(self):
        imports = {}

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name.split(".")[0]
                    imports[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    imports[local_name] = f"{module}.{alias.name}" if module else alias.name

        return imports

    def add_finding(self, node, category, issue, message, fix, origin=None, flow=None):
        line = getattr(node, "lineno", 1)
        severity = get_severity(issue)

        for f in self.findings:
            if f.category == category and f.issue.replace(" (sink)", "") == issue.replace(" (sink)", ""):
                if origin and f.origin == origin:
                    if line not in f.lines:
                        f.lines.append(line)
                        f.lines.sort()
                    if severity == "HIGH" and f.severity != "HIGH":
                        f.severity = "HIGH"
                        f.issue = issue
                    # Update flow chain if a richer one is provided
                    if flow and len(flow) > len(f.flow):
                        f.flow = flow
                    return
                elif not origin and line in f.lines:
                    if severity == "HIGH" and f.severity != "HIGH":
                        f.severity = "HIGH"
                        f.issue = issue
                    return

        finding = Finding(
            self.path, [line], category, issue, message, fix,
            severity, origin, flow or []
        )
        self.findings.append(finding)

    def is_password_name(self, name):
        lowered = name.lower()
        return any(token in lowered for token in PASSWORD_NAMES)

    def is_secret_name(self, name):
        lowered = name.lower()
        return any(token in lowered for token in SECRET_NAMES)

    def is_taint_source(self, node):
        if isinstance(node, ast.Call):
            full_name = get_full_name(node.func, self.imports)

            if full_name in {"input", "os.getenv"}:
                return True

            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                owner = get_full_name(node.func.value, self.imports)
                return name_matches(owner, REQUEST_SOURCES) or owner == "os.environ"

        if isinstance(node, ast.Subscript):
            owner = get_full_name(node.value, self.imports)
            return name_matches(owner, REQUEST_SOURCES) or owner in {"sys.argv", "os.environ"}

        return False

    def contains_taint(self, node):
        if node is None:
            return False

        if self.is_taint_source(node):
            return True

        if isinstance(node, ast.Name):
            return node.id in self.tainted_names

        if isinstance(node, ast.Attribute):
            return self.contains_taint(node.value)

        if isinstance(node, ast.BinOp):
            return self.contains_taint(node.left) or self.contains_taint(node.right)

        if isinstance(node, ast.BoolOp):
            return any(self.contains_taint(value) for value in node.values)

        if isinstance(node, ast.UnaryOp):
            return self.contains_taint(node.operand)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_return_funcs:
                return True
            full_call_name = get_full_name(node.func, self.imports)
            if full_call_name and full_call_name in self.tainted_return_funcs:
                return True
            return any(self.contains_taint(arg) for arg in node.args) or any(
                self.contains_taint(keyword.value) for keyword in node.keywords
            )

        if isinstance(node, ast.Subscript):
            return self.contains_taint(node.value) or self.contains_taint(node.slice)

        if isinstance(node, ast.JoinedStr):
            return any(self.contains_taint(value) for value in node.values)

        if isinstance(node, ast.FormattedValue):
            return self.contains_taint(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.contains_taint(value) for value in node.elts)

        if isinstance(node, ast.Dict):
            return any(self.contains_taint(key) for key in node.keys if key is not None) or any(
                self.contains_taint(value) for value in node.values
            )

        if isinstance(node, ast.IfExp):
            return any(
                self.contains_taint(part) for part in (node.test, node.body, node.orelse)
            )

        if isinstance(node, ast.Starred):
            return self.contains_taint(node.value)

        return False

    def contains_string_literal(self, node):
        if node is None:
            return False

        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)

        if isinstance(node, ast.JoinedStr):
            return True

        if isinstance(node, ast.BinOp):
            return self.contains_string_literal(node.left) or self.contains_string_literal(node.right)

        if isinstance(node, ast.Call):
            return any(self.contains_string_literal(arg) for arg in node.args)

        return False

    def looks_like_sql(self, node):
        combined = " ".join(lowered_literals(node))
        return any(keyword in combined for keyword in SQL_KEYWORDS)

    def looks_like_ldap(self, node):
        combined = " ".join(lowered_literals(node))
        return any(hint in combined for hint in LDAP_HINTS)

    def looks_like_html(self, node):
        combined = " ".join(lowered_literals(node))
        return any(hint in combined for hint in HTML_HINTS)

    def _get_assigned_value(self, var_name: str):
        result = None
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    for name in iter_target_names(target):
                        if name == var_name:
                            result = node.value
        return result

    def _looks_like_sql_expr(self, node) -> bool:
        if self.looks_like_sql(node):
            return True
        if isinstance(node, ast.Name) and node.id in self.tainted_names:
            assigned = self._get_assigned_value(node.id)
            if assigned is not None and self.looks_like_sql(assigned):
                return True
        return False

    def _looks_like_html_expr(self, node) -> bool:
        if self.looks_like_html(node):
            return True
        if isinstance(node, ast.Name) and node.id in self.tainted_names:
            assigned = self._get_assigned_value(node.id)
            if assigned is not None and self.looks_like_html(assigned):
                return True
        return False

    def is_format_string_call(self, node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and self.contains_string_literal(node.func.value)
        )

    def get_string_injection_details(self, node, style):
        if self.looks_like_sql(node):
            issue = "SQL injection"
        elif self.looks_like_ldap(node):
            issue = "LDAP injection"
        elif self.looks_like_html(node):
            issue = "Cross-site scripting (XSS)"
        else:
            return None, None, None

        return issue, STRING_INJECTION_MESSAGES[issue][style], STRING_INJECTION_FIXES[issue]

    def get_keyword(self, node, name):
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    def uses_safe_yaml_loader(self, node):
        loader = self.get_keyword(node, "Loader")
        if loader is None and len(node.args) > 1:
            loader = node.args[1]
        if loader is None:
            return False

        loader_name = get_full_name(loader, self.imports)
        return name_matches(loader_name, SAFE_YAML_LOADERS)

    def is_parameterized_execute(self, node: ast.Call) -> bool:
        args = node.args
        if isinstance(node.func, ast.Attribute) and node.func.attr == "executemany":
            return len(args) >= 2

        if len(args) >= 2:
            return True
        if self.get_keyword(node, "parameters") is not None:
            return True

        return False

    # ── [NEW] Path traversal severity helpers ─────────────────────────────────

    def _is_traversal_pattern(self, node) -> bool:
        """Return True only when the node contains an explicit directory traversal
        sequence (``../`` or ``..\\``). A bare ``/`` in a path prefix such as
        ``"files/"`` is not treated as traversal; that produces MEDIUM, not HIGH.
        """
        combined = " ".join(lowered_literals(node))
        return "../" in combined or "..\\" in combined

    # ── [NEW] Flow chain helpers ──────────────────────────────────────────────

    def get_flow_chain(self, var: str) -> list:
        """Reconstruct the taint propagation chain from the ultimate source to
        ``var`` by walking ``var_parent`` backwards, then reversing.

        e.g.  a = request.args["x"]; b = a; c = b
              get_flow_chain("c") → ["a", "b", "c"]
        """
        chain = [var]
        seen = {var}
        current = var
        while current in self.var_parent:
            parent = self.var_parent[current]
            if parent in seen or parent == current:
                break
            chain.append(parent)
            seen.add(parent)
            current = parent
        chain.reverse()
        return chain

    def _build_flow_for_origins(self, origins: set, sink_label: str) -> list:
        """Return a display-ready flow list for the first origin in ``origins``.

        Format: ["source_var", "intermediate", ..., sink_label]
        """
        if not origins:
            return []
        root = next(iter(origins))
        chain = self.get_flow_chain(root)
        return chain + [sink_label]

    # ─────────────────────────────────────────────────────────────────────────

    def collect_taint(self):
        """Fixed-point taint propagation with immediate-parent tracking."""
        outer_changed = True
        while outer_changed:
            outer_changed = False

            changed = True
            while changed:
                changed = False

                for node in ast.walk(self.tree):
                    if isinstance(node, ast.Assign):
                        if self.contains_taint(node.value):
                            rhs_vars = self._tainted_var_names(node.value)
                            origin = next(
                                (self.var_origin.get(v, v) for v in rhs_vars), None
                            )
                            # The direct predecessor is the first tainted var in the RHS.
                            immediate = next(iter(rhs_vars), None)
                            for target in node.targets:
                                for name in iter_target_names(target):
                                    if name not in self.tainted_names:
                                        self.tainted_names.add(name)
                                        self.var_origin[name] = origin or name
                                        # [NEW] Track immediate predecessor for chain display
                                        if immediate and immediate != name:
                                            self.var_parent[name] = immediate
                                        changed = True

                    elif isinstance(node, ast.AnnAssign):
                        if node.value is not None and self.contains_taint(node.value):
                            rhs_vars = self._tainted_var_names(node.value)
                            origin = next(
                                (self.var_origin.get(v, v) for v in rhs_vars), None
                            )
                            immediate = next(iter(rhs_vars), None)
                            for name in iter_target_names(node.target):
                                if name not in self.tainted_names:
                                    self.tainted_names.add(name)
                                    self.var_origin[name] = origin or name
                                    if immediate and immediate != name:
                                        self.var_parent[name] = immediate
                                    changed = True

                    elif isinstance(node, ast.AugAssign):
                        if self.contains_taint(node.value):
                            rhs_vars = self._tainted_var_names(node.value)
                            origin = next(
                                (self.var_origin.get(v, v) for v in rhs_vars), None
                            )
                            immediate = next(iter(rhs_vars), None)
                            for name in iter_target_names(node.target):
                                if name not in self.tainted_names:
                                    self.tainted_names.add(name)
                                    self.var_origin[name] = origin or name
                                    if immediate and immediate != name:
                                        self.var_parent[name] = immediate
                                    changed = True

            for node in ast.walk(self.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if node.name in self.tainted_return_funcs:
                    continue
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        if self.contains_taint(child.value):
                            self.tainted_return_funcs.add(node.name)
                            outer_changed = True
                            break

    def scan_hardcoded_secrets(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Assign):
                continue

            for target in node.targets:
                for name in iter_target_names(target):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if self.is_password_name(name):
                            self.add_finding(
                                node,
                                "Cryptographic Failures",
                                "Plaintext password",
                                "Password-like value is stored directly in source code.",
                                "Hash passwords with Argon2, bcrypt, or scrypt instead of storing raw values.",
                            )
                        elif self.is_secret_name(name):
                            self.add_finding(
                                node,
                                "Cryptographic Failures",
                                "Hardcoded secret",
                                "Secret-like value is hardcoded in source code.",
                                "Move secrets to a secure secret manager or environment variables.",
                            )

            if isinstance(node.value, ast.Dict):
                for key, value in zip(node.value.keys, node.value.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            if self.is_password_name(key.value):
                                self.add_finding(
                                    node,
                                    "Cryptographic Failures",
                                    "Plaintext password",
                                    "Password field contains a plaintext string literal.",
                                    "Store password hashes only, never plaintext passwords.",
                                )
                            elif self.is_secret_name(key.value):
                                self.add_finding(
                                    node,
                                    "Cryptographic Failures",
                                    "Hardcoded secret",
                                    "Secret field contains a hardcoded string literal.",
                                    "Load secrets from a secure store instead of source code.",
                                )

    def scan_weak_hashes(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue

            full_name = get_full_name(node.func, self.imports)

            if full_name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                algorithm = full_name.split(".")[-1]
                self.add_finding(
                    node,
                    "Cryptographic Failures",
                    "Weak hash",
                    f"Weak hash function `{algorithm}` is used.",
                    "Use a stronger algorithm. For passwords, prefer Argon2, bcrypt, or scrypt.",
                )

            if full_name == "hashlib.new" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    algorithm = first_arg.value.lower()
                    if algorithm in WEAK_HASHES:
                        self.add_finding(
                            node,
                            "Cryptographic Failures",
                            "Weak hash",
                            f"Weak hash function `{algorithm}` is used.",
                            "Use a stronger algorithm. For passwords, prefer Argon2, bcrypt, or scrypt.",
                        )

    def _tainted_var_names(self, node) -> set:
        names = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_names:
                names.add(child.id)
        return names

    def _already_reported_for_origins(self, issue: str, origins: set, sink_line: int = None) -> bool:
        return bool(origins) and all(
            (issue, o, sink_line) in self._reported_taint_issues for o in origins
        )

    def _record_taint_report_origins(self, issue: str, origins: set, sink_line: int = None) -> None:
        for o in origins:
            self._reported_taint_issues.add((issue, o, sink_line))

    def _already_reported_for_vars(self, issue: str, var_names: set) -> bool:
        origins = {self.var_origin.get(v, v) for v in var_names}
        return self._already_reported_for_origins(issue, origins)

    def _record_taint_report(self, issue: str, node) -> None:
        for name in self._tainted_var_names(node):
            origin = self.var_origin.get(name, name)
            self._reported_taint_issues.add((issue, origin, None))
        for tree_node in ast.walk(self.tree):
            if isinstance(tree_node, ast.Assign) and tree_node.value is node:
                for target in tree_node.targets:
                    for name in iter_target_names(target):
                        origin = self.var_origin.get(name, name)
                        self._reported_taint_issues.add((issue, origin, None))

    def scan_injection(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue

            full_name = get_full_name(node.func, self.imports)

            # ── DB execute sink ───────────────────────────────────────────────
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
                if not self.is_parameterized_execute(node):
                    for arg in node.args:
                        if self.contains_taint(arg):
                            vars_in_arg = self._tainted_var_names(arg)
                            origins = {self.var_origin.get(v, v) for v in vars_in_arg}

                            if not self._looks_like_sql_expr(arg):
                                continue

                            if not self._already_reported_for_origins("SQL injection", origins, node.lineno):
                                flow = self._build_flow_for_origins(origins, "execute()")
                                self.add_finding(
                                    node,
                                    "Injection",
                                    "SQL injection (sink)",
                                    "Tainted data reaches a database execution sink without parameterization.",
                                    "Use parameterized queries and keep untrusted input out of raw SQL strings.",
                                    origin=next(iter(origins), None),
                                    flow=flow,
                                )
                                self._record_taint_report_origins("SQL injection", origins, node.lineno)
                            break

            # ── OS command sinks ──────────────────────────────────────────────
            if full_name in COMMAND_SINKS:
                for arg in node.args:
                    if self.contains_taint(arg):
                        vars_in_arg = self._tainted_var_names(arg)
                        origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                        flow = self._build_flow_for_origins(origins, full_name)
                        self.add_finding(
                            node,
                            "Injection",
                            "OS command injection",
                            "Tainted data reaches an OS command execution sink.",
                            "Avoid shell execution with raw input; validate input and prefer safe argument lists.",
                            origin=next(iter(origins), None),
                            flow=flow,
                        )
                        break

            # ── Subprocess with shell=True ────────────────────────────────────
            if full_name in SUBPROCESS_SINKS:
                shell_value = self.get_keyword(node, "shell")
                if isinstance(shell_value, ast.Constant) and shell_value.value is True:
                    for arg in node.args:
                        if self.contains_taint(arg):
                            vars_in_arg = self._tainted_var_names(arg)
                            origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                            flow = self._build_flow_for_origins(origins, full_name)
                            self.add_finding(
                                node,
                                "Injection",
                                "OS command injection",
                                "Tainted data reaches a subprocess call with `shell=True`.",
                                "Remove `shell=True` when possible and pass validated arguments as a list.",
                                origin=next(iter(origins), None),
                                flow=flow,
                            )
                            break

            # ── LDAP sinks ────────────────────────────────────────────────────
            if isinstance(node.func, ast.Attribute) and node.func.attr in LDAP_SINKS:
                for arg in node.args:
                    if self.contains_taint(arg):
                        vars_in_arg = self._tainted_var_names(arg)
                        origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                        if not self._already_reported_for_origins("LDAP injection", origins, node.lineno):
                            flow = self._build_flow_for_origins(origins, "search()")
                            self.add_finding(
                                node,
                                "Injection",
                                "LDAP injection",
                                "Tainted data reaches an LDAP search sink.",
                                "Build LDAP filters safely and escape untrusted input.",
                                origin=next(iter(origins), None),
                                flow=flow,
                            )
                            self._record_taint_report_origins("LDAP injection", origins, node.lineno)
                        break

    def scan_xss(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                if self.contains_taint(node.value) and self._looks_like_html_expr(node.value):
                    vars_in_node = self._tainted_var_names(node.value)
                    origins = {self.var_origin.get(v, v) for v in vars_in_node}
                    flow = self._build_flow_for_origins(origins, "html_assign")
                    self.add_finding(
                        node,
                        "Injection",
                        "Cross-site scripting (XSS)",
                        "Untrusted input is assigned to an HTML-like string.",
                        "Escape untrusted output or use a templating engine with auto-escaping.",
                        origin=next(iter(origins), None),
                        flow=flow,
                    )

            if isinstance(node, ast.Return) and node.value is not None:
                if self.contains_taint(node.value) and self._looks_like_html_expr(node.value):
                    vars_in_node = self._tainted_var_names(node.value)
                    origins = {self.var_origin.get(v, v) for v in vars_in_node}
                    flow = self._build_flow_for_origins(origins, "return")
                    self.add_finding(
                        node,
                        "Injection",
                        "Cross-site scripting (XSS)",
                        "Untrusted input is returned as HTML.",
                        "Escape untrusted output or use a templating engine with auto-escaping.",
                        origin=next(iter(origins), None),
                        flow=flow,
                    )

            if isinstance(node, ast.Call):
                full_name = get_full_name(node.func, self.imports)
                if full_name in {"print", "builtins.print"}:
                    for arg in node.args:
                        if self.contains_taint(arg) and self._looks_like_html_expr(arg):
                            vars_in_arg = self._tainted_var_names(arg)
                            origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                            flow = self._build_flow_for_origins(origins, "print()")
                            self.add_finding(
                                node,
                                "Injection",
                                "Cross-site scripting (XSS)",
                                "Untrusted input is printed as HTML.",
                                "Escape untrusted output or use a templating engine with auto-escaping.",
                                origin=next(iter(origins), None),
                                flow=flow,
                            )

    def scan_path_traversal(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue

            full_name = get_full_name(node.func, self.imports)
            if full_name not in FILE_SINKS:
                continue

            for arg in node.args:
                if self.contains_taint(arg):
                    # [FIX] Only escalate to HIGH when an explicit traversal
                    # sequence (../ or ..\) is present in the literal parts of
                    # the path expression.  A plain prefix like "files/" is
                    # MEDIUM — it restricts nothing but is not guaranteed traversal.
                    if self._is_traversal_pattern(arg):
                        issue = "Path Traversal (High Severity)"
                    else:
                        issue = "User-controlled file path"

                    vars_in_arg = self._tainted_var_names(arg)
                    origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                    flow = self._build_flow_for_origins(origins, "open()")
                    self.add_finding(
                        node,
                        "Path Traversal",
                        issue,
                        "Tainted input is used to build a filesystem path.",
                        "Validate filenames against an allowlist and resolve paths safely before opening files.",
                        origin=next(iter(origins), None),
                        flow=flow,
                    )
                    break

    def scan_misconfiguration(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                debug_value = self.get_keyword(node, "debug")
                if isinstance(debug_value, ast.Constant) and debug_value.value is True:
                    self.add_finding(
                        node,
                        "Security Misconfiguration",
                        "Debug mode enabled",
                        "Application debug mode is enabled.",
                        "Disable debug mode in production.",
                    )

                host_value = self.get_keyword(node, "host")
                if isinstance(host_value, ast.Constant) and host_value.value == "0.0.0.0":
                    self.add_finding(
                        node,
                        "Security Misconfiguration",
                        "Exposed service binding",
                        "Application binds to `0.0.0.0`.",
                        "Bind only to required interfaces and restrict network exposure.",
                    )

                if isinstance(node.func, ast.Attribute) and node.func.attr == "bind" and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Tuple) and first_arg.elts:
                        host_node = first_arg.elts[0]
                        if isinstance(host_node, ast.Constant) and host_node.value == "0.0.0.0":
                            self.add_finding(
                                node,
                                "Security Misconfiguration",
                                "Exposed service binding",
                                "Socket binds to `0.0.0.0`.",
                                "Bind only to required interfaces and restrict network exposure.",
                            )

            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.upper() == "DEBUG":
                            self.add_finding(
                                node,
                                "Security Misconfiguration",
                                "Debug mode enabled",
                                "Debug flag is set to true.",
                                "Disable debug mode in production settings.",
                            )

    def scan_integrity_failures(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue

            full_name = get_full_name(node.func, self.imports)

            if full_name in {"pickle.loads", "pickle.load"}:
                self.add_finding(
                    node,
                    "Software & Data Integrity Failures",
                    "Unsafe deserialization",
                    "Pickle deserialization can execute attacker-controlled data.",
                    "Avoid untrusted pickle data; prefer safer formats like JSON.",
                )

            if full_name in {"eval", "builtins.eval", "exec", "builtins.exec"}:
                self.add_finding(
                    node,
                    "Software & Data Integrity Failures",
                    "Dynamic code execution",
                    "Dynamic code execution function is used.",
                    "Replace `eval` or `exec` with safe parsing or a strict allowlist.",
                )

            if full_name == "yaml.load" and not self.uses_safe_yaml_loader(node):
                self.add_finding(
                    node,
                    "Software & Data Integrity Failures",
                    "Unsafe YAML load",
                    "Unsafe YAML loading can deserialize untrusted objects.",
                    "Use `yaml.safe_load` for untrusted YAML.",
                )

    def scan_ssrf(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue

            full_name = get_full_name(node.func, self.imports)
            if full_name not in SSRF_SINKS:
                continue

            url_args = []
            if node.args:
                url_args.append(node.args[0])

            url_keyword = self.get_keyword(node, "url")
            if url_keyword is not None:
                url_args.append(url_keyword)

            for arg in url_args:
                if self.contains_taint(arg):
                    issue = "User-controlled URL request"
                    combined = " ".join(lowered_literals(arg))
                    if re.search(r"127\.|192\.168\.|10\.|169\.254\.|0\.0\.0\.0|localhost", combined):
                        issue = "Server-Side Request Forgery (SSRF) - Internal"

                    vars_in_arg = self._tainted_var_names(arg)
                    origins = {self.var_origin.get(v, v) for v in vars_in_arg}
                    flow = self._build_flow_for_origins(origins, full_name)
                    self.add_finding(
                        node,
                        "Server-Side Request Forgery (SSRF)",
                        issue,
                        "Tainted input is used as an outbound request target.",
                        "Validate and allowlist outbound destinations before making requests.",
                        origin=next(iter(origins), None),
                        flow=flow,
                    )
                    break

    def scan(self):
        self.collect_taint()
        self.scan_hardcoded_secrets()
        self.scan_weak_hashes()
        self.scan_injection()
        self.scan_xss()
        self.scan_path_traversal()
        self.scan_misconfiguration()
        self.scan_integrity_failures()
        self.scan_ssrf()
        return sort_findings(self.findings)


def scan_config_file(path: Path):
    findings = []
    seen = set()

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";", "//")):
            continue

        for pattern, message, fix in DEBUG_PATTERNS:
            if pattern.match(stripped):
                severity = get_severity(message)
                finding = Finding(
                    path=path,
                    lines=[line_number],
                    category="Security Misconfiguration",
                    issue=message,
                    message=message,
                    fix=fix,
                    severity=severity,
                    origin=None,
                    flow=[],
                )
                key = finding_identity(finding)
                if key not in seen:
                    findings.append(finding)
                    seen.add(key)

    return sort_findings(findings)


def scan_python_file(path: Path):
    try:
        code = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"Skipping {short_path(path)}: unable to decode as UTF-8.")
        return []

    try:
        return PythonSecurityScanner(path, code).scan()
    except SyntaxError as error:
        print(
            f"Skipping {short_path(path)}: syntax error on line {error.lineno} — {error.msg}"
        )
        return []


def scan_target(target: Path):
    findings = []

    for path in iter_targets(target):
        if path.suffix == ".py":
            findings.extend(scan_python_file(path))
        elif is_config_file(path):
            findings.extend(scan_config_file(path))

    return sort_findings(findings)


SEVERITY_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[96m",
    "RESET":  "\033[0m",
}


def _color(text, color_key):
    return f"{SEVERITY_COLORS[color_key]}{text}{SEVERITY_COLORS['RESET']}"


def print_report(findings, *, use_color: bool = True):
    if not findings:
        print("No supported vulnerabilities found.")
    else:
        current_severity = None
        for finding in findings:
            if finding.severity != current_severity:
                current_severity = finding.severity
                label = f"[{current_severity}]"
                header = _color(label, current_severity) if use_color else label
                print(f"\n{header}")

            sev_tag = f"[{finding.severity}]"
            if use_color:
                sev_tag = _color(sev_tag, finding.severity)

            display_issue = finding.issue.replace(" (sink)", "")

            # [NEW] Grouped sink format for taint findings with multiple lines
            if finding.origin and len(finding.lines) > 1:
                print(f"  {short_path(finding.path)} | {finding.category} | {display_issue} (Origin: `{finding.origin}`)")
                print(f"    Issue : {finding.message}")
                print(f"    Fix   : {finding.fix}")
                print(f"    Sinks :")
                for ln in finding.lines:
                    print(f"      - line {ln}")
            else:
                if len(finding.lines) > 1:
                    loc = f"{short_path(finding.path)}:{', '.join(map(str, finding.lines))}"
                else:
                    loc = f"{short_path(finding.path)}:{finding.lines[0]}"
                print(f"  {loc} | {finding.category} | {display_issue}")
                print(f"    Issue : {finding.message}")
                print(f"    Fix   : {finding.fix}")
                if finding.origin:
                    print(f"    Origin: `{finding.origin}`")

            # [NEW] Flow chain — only shown when there are at least 2 hops
            if finding.flow and len(finding.flow) >= 2:
                print(f"    Flow  : {' → '.join(finding.flow)}")

    print("\nSkipped categories (not in scope):")
    for category in UNSUPPORTED_CATEGORIES:
        print(f"  - {category}")


def main():
    parser = argparse.ArgumentParser(
        description="Static security scanner for Python projects."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="File or directory to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output.",
    )
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        raise SystemExit(f"Target not found: {args.target}")

    findings = scan_target(target)
    print_report(findings, use_color=not args.no_color)


if __name__ == "__main__":
    main()
