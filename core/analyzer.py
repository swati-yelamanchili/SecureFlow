import ast
import os
import importlib
import sys

from analysis.framework import detect_framework


class SecurityContext:
    """Shared context passed to every plugin during a scan."""

    def __init__(self, code, tree):
        self.code = code
        self.tree = tree
        self.imports = []
        self.framework = "unknown"


class Analyzer:
    """Core engine: parses code, loads plugins, collects findings."""

    def __init__(self):
        self.findings = []
        self.plugins = []

    def load_plugins(self):
        plugin_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
        plugin_dir = os.path.abspath(plugin_dir)

        # Ensure project root is importable
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        for filename in sorted(os.listdir(plugin_dir)):
            if filename.endswith(".py") and filename not in ("__init__.py", "base.py"):
                module_name = f"plugins.{filename[:-3]}"
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and attr.__name__ != "BaseScannerPlugin"
                        and "Plugin" in attr.__name__
                    ):
                        self.plugins.append(attr(self))

    def add_finding(self, node, category, issue, message, fix):
        self.findings.append(
            {
                "line": getattr(node, "lineno", None) if node else None,
                "category": category,
                "issue": issue,
                "message": message,
                "fix": fix,
            }
        )

    def analyze(self, code):
        tree = ast.parse(code)
        context = SecurityContext(code, tree)

        # Collect imports for framework detection
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    context.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    context.imports.append(node.module)

        context.framework = detect_framework(context.imports)

        for plugin in self.plugins:
            plugin.scan(tree, context)

        return self.findings
