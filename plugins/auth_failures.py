import ast
from plugins.base import BaseScannerPlugin


class AuthFailuresPlugin(BaseScannerPlugin):
    """A07 — Identification and Authentication Failures.

    Detects plaintext password comparisons and weak auth logic.
    """

    def scan(self, tree, context):
        for node in ast.walk(tree):
            # Plaintext password comparison: if password == "..."
            if isinstance(node, ast.Compare):
                left_name = ""
                if isinstance(node.left, (ast.Name, ast.Attribute)):
                    left_name = self.get_full_name(node.left)
                if "password" in left_name.lower():
                    for op, comparator in zip(node.ops, node.comparators):
                        if isinstance(op, ast.Eq):
                            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                                self.scanner.add_finding(
                                    node,
                                    "Identification and Authentication Failures",
                                    "Plaintext Password Comparison",
                                    "Password is being compared in plaintext.",
                                    "Use a secure hashing algorithm (e.g. bcrypt/argon2) to verify passwords.",
                                )

            # Hardcoded password stored directly
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and "password" in target.id.lower():
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            self.scanner.add_finding(
                                node,
                                "Identification and Authentication Failures",
                                "Hardcoded Password",
                                f"Password stored in plaintext in variable '{target.id}'.",
                                "Hash passwords with bcrypt or Argon2 before storage.",
                            )
