import ast
from plugins.base import BaseScannerPlugin


class LoggingMonitoringPlugin(BaseScannerPlugin):
    """A09 — Security Logging and Monitoring Failures.

    Flags sensitive operations (login, payment, delete) that lack logging.
    """

    def scan(self, tree, context):
        sensitive_keywords = {
            "login", "authenticate", "transfer",
            "payment", "delete_account", "reset_password",
        }

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            if not any(k in node.name.lower() for k in sensitive_keywords):
                continue

            has_logging = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = self.get_full_name(child.func)
                    if name and ("log" in name.lower() or "print" in name.lower()):
                        has_logging = True
                        break

            if not has_logging:
                self.scanner.add_finding(
                    node,
                    "Security Logging and Monitoring Failures",
                    "Missing Logging",
                    f"Sensitive operation '{node.name}' does not implement logging.",
                    "Add logging to audit sensitive transactions and administrative actions.",
                )
