import ast


class BaseScannerPlugin:
    """Base class for all scanner plugins."""

    def __init__(self, scanner):
        self.scanner = scanner

    def scan(self, tree, context):
        raise NotImplementedError

    def get_full_name(self, node):
        """Resolve a dotted name from an AST node (e.g. 'os.path.join')."""
        if isinstance(node, ast.Attribute):
            base = self.get_full_name(node.value)
            if base:
                return base + "." + node.attr
            return node.attr
        elif isinstance(node, ast.Name):
            return node.id
        return ""
