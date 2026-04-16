import os
from plugins.base import BaseScannerPlugin


MOCK_VULNERABLE = {
    "django": ("< 3.0", "Upgrade to Django >= 3.0"),
    "flask": ("< 1.0", "Upgrade to Flask >= 1.0"),
    "requests": ("< 2.20", "Upgrade to Requests >= 2.20"),
    "pyyaml": ("< 5.1", "Upgrade to PyYAML >= 5.1"),
    "jinja2": ("< 2.10.1", "Upgrade to Jinja2 >= 2.10.1"),
}


class VulnComponentsPlugin(BaseScannerPlugin):
    """A06 — Vulnerable and Outdated Components.

    Parses requirements.txt and flags known-vulnerable packages (mock list).
    """

    def scan(self, tree, context):
        req_path = os.path.join(os.getcwd(), "requirements.txt")
        if not os.path.exists(req_path):
            return

        with open(req_path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue

                pkg_name = line.split("==")[0].split(">=")[0].split("<=")[0].split("<")[0].split(">")[0].strip()
                if pkg_name in MOCK_VULNERABLE:
                    version_info, fix = MOCK_VULNERABLE[pkg_name]
                    self.scanner.add_finding(
                        None,
                        "Vulnerable and Outdated Components",
                        "Vulnerable Package",
                        f"Package '{pkg_name}' may be vulnerable ({version_info}).",
                        fix,
                    )
