import ast
from plugins.base import BaseScannerPlugin
from core.taint_engine import TaintEngine, is_user_input


class InjectionPlugin(BaseScannerPlugin):
    """A03 — Injection.

    Detects SQL injection, OS command injection, and eval/exec misuse
    by combining taint analysis with sink matching.
    """

    def scan(self, tree, context):
        taint = TaintEngine()
        taint.propagate(tree)

        sql_sinks = {"execute", "executemany", "raw"}
        os_sinks = {"os.system", "os.popen", "subprocess.call",
                     "subprocess.run", "subprocess.Popen",
                     "subprocess.check_output"}
        eval_sinks = {"eval", "exec"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = self.get_full_name(node.func)
            if not name:
                continue

            name_lower = name.lower()
            is_sql = any(k in name_lower for k in sql_sinks)
            is_os = name in os_sinks
            is_eval = name in eval_sinks

            if is_sql or is_os or is_eval:
                for arg in node.args:
                    if is_user_input(arg) or taint._check_taint(arg):
                        if is_sql:
                            issue = "SQL Injection"
                        elif is_os:
                            issue = "OS Command Injection"
                        else:
                            issue = "Code Injection (eval/exec)"

                        self.scanner.add_finding(
                            node,
                            "Injection",
                            issue,
                            f"Tainted input reaches dangerous sink: {name}",
                            "Sanitize or parameterize inputs.",
                        )
                        break
