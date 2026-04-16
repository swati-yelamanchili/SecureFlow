import ast


def is_user_input(node):
    """Check whether an AST node looks like user-controlled input."""
    try:
        name = ast.unparse(node).lower()
    except Exception:
        return False
    return any(
        x in name
        for x in ["request", "body", "json", "args", "form", "input", "getenv"]
    )


class TaintEngine:
    """Tracks tainted variables and propagates taint through assignments."""

    def __init__(self):
        self.tainted_vars = set()

    def mark_tainted(self, var_name):
        self.tainted_vars.add(var_name)

    def is_tainted(self, var_name):
        return var_name in self.tainted_vars

    def propagate(self, tree):
        """Walk the tree and propagate taint from sources to targets."""
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    if is_user_input(node.value) or self._check_taint(node.value):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                if target.id not in self.tainted_vars:
                                    self.mark_tainted(target.id)
                                    changed = True

    def _check_taint(self, node):
        """Return True if the node references any tainted variable."""
        if isinstance(node, ast.Name):
            return self.is_tainted(node.id)
        if isinstance(node, ast.BinOp):
            return self._check_taint(node.left) or self._check_taint(node.right)
        if isinstance(node, ast.Call):
            return any(self._check_taint(arg) for arg in node.args)
        if isinstance(node, ast.JoinedStr):
            return any(self._check_taint(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._check_taint(node.value)
        if isinstance(node, ast.Subscript):
            return self._check_taint(node.value)
        if isinstance(node, ast.Attribute):
            return self._check_taint(node.value)
        return False
