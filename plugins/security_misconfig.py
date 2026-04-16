import ast
from plugins.base import BaseScannerPlugin


class SecurityMisconfigPlugin(BaseScannerPlugin):
    """A05 — Security Misconfiguration.

    Detects debug mode, open CORS, and unsafe configuration patterns.
    """

    def scan(self, tree, context):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # debug=True  in any call
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.scanner.add_finding(
                        node,
                        "Security Misconfiguration",
                        "Debug Mode Enabled",
                        "Application runs with debug=True.",
                        "Disable debug mode in production.",
                    )

            # Permissive CORS (origins="*")
            name = self.get_full_name(node.func)
            if name and "cors" in name.lower():
                for kw in node.keywords:
                    if kw.arg == "origins" and isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                        self.scanner.add_finding(
                            node,
                            "Security Misconfiguration",
                            "Permissive CORS",
                            "CORS origins configured to '*'.",
                            "Restrict CORS origins to trusted domains.",
                        )

            # host="0.0.0.0" binding
            for kw in node.keywords:
                if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                    self.scanner.add_finding(
                        node,
                        "Security Misconfiguration",
                        "Exposed Service Binding",
                        "Application binds to 0.0.0.0.",
                        "Bind only to required interfaces.",
                    )

        # DEBUG = True assignment
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.upper() == "DEBUG":
                            self.scanner.add_finding(
                                node,
                                "Security Misconfiguration",
                                "Debug Mode Enabled",
                                "Debug flag is set to True.",
                                "Disable debug mode in production settings.",
                            )
