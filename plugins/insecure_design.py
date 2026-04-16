import ast
from plugins.base import BaseScannerPlugin


class InsecureDesignPlugin(BaseScannerPlugin):
    """A04 — Insecure Design.

    Flags data model / schema classes that lack validation methods.
    """

    def scan(self, tree, context):
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                name_lower = node.name.lower()
                if "model" not in name_lower and "schema" not in name_lower:
                    continue

                has_validation = False
                for child in ast.walk(node):
                    if isinstance(child, ast.FunctionDef) and "validate" in child.name.lower():
                        has_validation = True
                        break

                if not has_validation:
                    self.scanner.add_finding(
                        node,
                        "Insecure Design",
                        "Missing Validation",
                        f"Data model or schema class '{node.name}' lacks validation logic.",
                        "Implement validation methods to ensure data integrity.",
                    )
