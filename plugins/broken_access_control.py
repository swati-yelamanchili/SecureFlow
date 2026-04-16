import ast
from plugins.base import BaseScannerPlugin
from analysis.auth_tracker import AuthTracker
from analysis.framework import is_route_decorator


class BrokenAccessControlPlugin(BaseScannerPlugin):
    """A01 — Broken Access Control.

    Flags route handlers that interact with the database but lack
    both decorator-based and inline authentication checks.
    """

    def scan(self, tree, context):
        db_keywords = {
            "execute", "query", "find", "commit",
            "delete", "insert", "update", "select",
        }

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_route = False
            has_auth_decorator = False
            has_db = False

            auth_tracker = AuthTracker()

            # ── Decorator analysis ──────────────────────────────────────────
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call):
                    name = self.get_full_name(decorator.func)
                else:
                    name = self.get_full_name(decorator)

                if not name:
                    continue

                if is_route_decorator(name, context.framework):
                    is_route = True

                if any(x in name.lower() for x in ["auth", "login", "permission", "jwt", "role"]):
                    has_auth_decorator = True

            # ── Body analysis ───────────────────────────────────────────────
            for child in ast.walk(node):
                if isinstance(child, ast.If):
                    auth_tracker.process_if(child)

                if isinstance(child, ast.Call):
                    call_name = self.get_full_name(child.func)
                    if call_name and any(k in call_name.lower() for k in db_keywords):
                        has_db = True

            # ── Decision ────────────────────────────────────────────────────
            if is_route and has_db and not (has_auth_decorator or auth_tracker.authenticated_paths):
                self.scanner.add_finding(
                    node,
                    "Broken Access Control",
                    "Missing Access Control",
                    "Route with database access lacks proper access control.",
                    "Add authentication/authorization checks.",
                )
