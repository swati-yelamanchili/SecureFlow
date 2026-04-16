import ast


class CFGNode:
    """Single node in a simplified control-flow graph."""

    def __init__(self, ast_node):
        self.ast_node = ast_node
        self.children = []


class SimpleCFG:
    """Basic control-flow graph supporting if/else and return tracking."""

    def __init__(self, func_node):
        self.root = CFGNode(func_node)
        self.has_return = False
        self._build(func_node)

    def _build(self, node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Return):
                self.has_return = True
            self._build(child)

    def tracks_if_else(self, node):
        """Return True if the node contains an if with an else branch."""
        has_if = False
        has_else = False
        for child in ast.walk(node):
            if isinstance(child, ast.If):
                has_if = True
                if child.orelse:
                    has_else = True
        return has_if and has_else
