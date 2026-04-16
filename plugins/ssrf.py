import ast
from plugins.base import BaseScannerPlugin
from core.taint_engine import TaintEngine, is_user_input


class SSRFPlugin(BaseScannerPlugin):
    """A10 — Server-Side Request Forgery (SSRF).

    Detects user-controlled input used in outbound HTTP requests.
    """

    def scan(self, tree, context):
        taint = TaintEngine()
        taint.propagate(tree)

        http_sinks = {
            "requests.get", "requests.post", "requests.put",
            "requests.patch", "requests.delete", "requests.head",
            "urllib.request.urlopen",
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = self.get_full_name(node.func)
            if name not in http_sinks:
                continue

            if node.args:
                arg = node.args[0]
                if is_user_input(arg) or taint._check_taint(arg):
                    self.scanner.add_finding(
                        node,
                        "Server-Side Request Forgery",
                        "SSRF",
                        f"Tainted input used in HTTP request: {name}",
                        "Validate and restrict URLs before making HTTP requests.",
                    )
