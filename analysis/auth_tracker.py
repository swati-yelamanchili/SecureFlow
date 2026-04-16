import ast


class AuthTracker:
    """Detects authentication checks inside function bodies."""

    def __init__(self):
        self.authenticated_paths = False

    def check_if_auth_condition(self, node):
        """Return True if the if-condition references auth-related keywords."""
        try:
            cond = ast.unparse(node).lower()
        except Exception:
            return False

        keywords = [
            "auth", "authenticated", "user", "token",
            "session", "permission", "role", "login",
        ]
        return any(k in cond for k in keywords)

    def process_if(self, node):
        """Mark route as having an inline auth check when the condition matches."""
        if self.check_if_auth_condition(node.test):
            self.authenticated_paths = True