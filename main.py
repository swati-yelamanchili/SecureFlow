#!/usr/bin/env python3
"""SecureFlow — Modular static security scanner for OWASP Top 10."""

import argparse
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.analyzer import Analyzer


SEVERITY_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[96m",
    "RESET":  "\033[0m",
}


def colorize(text, level):
    color = SEVERITY_COLORS.get(level, "")
    reset = SEVERITY_COLORS["RESET"]
    return f"{color}{text}{reset}"


def classify_severity(issue):
    high = {"Missing Access Control", "SQL Injection", "OS Command Injection",
            "Code Injection (eval/exec)", "Unsafe Deserialization", "SSRF"}
    medium = {"Weak Hash Algorithm", "Debug Mode Enabled", "Permissive CORS",
              "Exposed Service Binding", "Missing Validation", "Vulnerable Package"}
    if issue in high:
        return "HIGH"
    if issue in medium:
        return "MEDIUM"
    return "LOW"


def print_report(findings, use_color=True):
    if not findings:
        print("\n  ✅  No vulnerabilities found.")
        return

    # Sort by severity
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in findings:
        f["severity"] = classify_severity(f["issue"])
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    current_sev = None
    for f in findings:
        if f["severity"] != current_sev:
            current_sev = f["severity"]
            label = f"[{current_sev}]"
            if use_color:
                label = colorize(label, current_sev)
            print(f"\n{label}")

        line = f["line"]
        loc = f"line {line}" if line else "N/A"
        print(f"  {loc} | {f['category']} | {f['issue']}")
        print(f"    Issue : {f['message']}")
        print(f"    Fix   : {f['fix']}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureFlow — static security scanner for Python projects."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Python file or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"Error: target not found: {args.target}")
        sys.exit(1)

    # Collect .py files
    py_files = []
    ignored = {".git", "__pycache__", "venv", ".venv", "env", "node_modules",
               "core", "analysis", "plugins", "security"}

    if os.path.isfile(target):
        py_files.append(target)
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ignored]
            for f in files:
                if f.endswith(".py") and f != "main.py":
                    py_files.append(os.path.join(root, f))

    analyzer = Analyzer()
    analyzer.load_plugins()

    for filepath in sorted(py_files):
        try:
            code = open(filepath, "r", encoding="utf-8").read()
        except (UnicodeDecodeError, OSError) as e:
            print(f"Skipping {filepath}: {e}")
            continue

        try:
            analyzer.analyze(code)
        except SyntaxError as e:
            print(f"Skipping {filepath}: syntax error — {e.msg}")

    print_report(analyzer.findings, use_color=not args.no_color)


if __name__ == "__main__":
    main()
