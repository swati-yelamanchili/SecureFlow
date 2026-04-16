import ast
from plugins.base import BaseScannerPlugin


class DataIntegrityPlugin(BaseScannerPlugin):
    """A08 — Software and Data Integrity Failures.

    Detects unsafe deserialization via pickle and yaml.load.
    """

    def scan(self, tree, context):
        unsafe_sinks = {"pickle.load", "pickle.loads", "yaml.load"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = self.get_full_name(node.func)
            if name not in unsafe_sinks:
                continue

            # yaml.load with SafeLoader is acceptable
            if name == "yaml.load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        val = self.get_full_name(kw.value)
                        if val and "safeloader" in val.lower():
                            has_safe_loader = True
                if len(node.args) > 1:
                    val = self.get_full_name(node.args[1])
                    if val and "safeloader" in val.lower():
                        has_safe_loader = True
                if has_safe_loader:
                    continue

            self.scanner.add_finding(
                node,
                "Software and Data Integrity Failures",
                "Unsafe Deserialization",
                f"Usage of unsafe deserialization function: {name}.",
                "Use safe alternatives like json.loads() or yaml.safe_load().",
            )
