import ast
from plugins.base import BaseScannerPlugin


class CryptoFailuresPlugin(BaseScannerPlugin):
    """A02 — Cryptographic Failures.

    Detects weak hash algorithms (MD5, SHA-1) and hardcoded secrets.
    """

    def scan(self, tree, context):
        weak_hashes = {"md5", "sha1"}
        secret_keys = {"password", "secret", "api_key", "token", "private_key"}

        for node in ast.walk(tree):
            # Weak hash usage
            if isinstance(node, ast.Call):
                name = self.get_full_name(node.func)
                if name and any(wh in name.lower() for wh in weak_hashes):
                    self.scanner.add_finding(
                        node,
                        "Cryptographic Failures",
                        "Weak Hash Algorithm",
                        f"Usage of weak hash algorithm: {name}",
                        "Use strong algorithms like SHA-256 or bcrypt/Argon2.",
                    )

            # Hardcoded secrets
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if any(sk in target.id.lower() for sk in secret_keys):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                if len(node.value.value) > 0:
                                    self.scanner.add_finding(
                                        node,
                                        "Cryptographic Failures",
                                        "Hardcoded Secret",
                                        f"Hardcoded sensitive value assigned to '{target.id}'.",
                                        "Store sensitive information in environment variables or a secret manager.",
                                    )
