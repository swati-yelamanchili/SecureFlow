<div align="center">

# 🛡️ SecureFlow

**A modular static security scanner for Python projects — covering the OWASP Top 10.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-orange.svg)](https://owasp.org/www-project-top-ten/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#requirements)

</div>

---

SecureFlow analyzes Python source code **without executing it**. It uses AST-based static analysis and taint tracking to detect vulnerabilities across all 10 OWASP categories — from injection flaws to missing logging — in a clean, plugin-based architecture.

## ✨ Features

- 🔌 **Plugin architecture** — one file per OWASP category, easy to extend
- 🌊 **Taint engine** — tracks user input flowing from sources to dangerous sinks
- 🔍 **Framework-aware** — detects Flask, FastAPI, and Django route patterns
- 🎯 **Severity classification** — findings grouped as `HIGH`, `MEDIUM`, or `LOW`
- 📦 **Zero dependencies** — uses only the Python standard library
- 🎨 **Color-coded output** — terminal-friendly with `--no-color` fallback

## 📋 OWASP Top 10 Coverage

| # | Category | Plugin | Key Detections |
|---|----------|--------|----------------|
| A01 | Broken Access Control | `broken_access_control.py` | Routes with DB access missing auth decorators/checks |
| A02 | Cryptographic Failures | `crypto_failures.py` | Weak hashes (MD5/SHA-1), hardcoded secrets |
| A03 | Injection | `injection.py` | SQL injection, OS command injection, eval/exec misuse |
| A04 | Insecure Design | `insecure_design.py` | Model/schema classes lacking validation |
| A05 | Security Misconfiguration | `security_misconfig.py` | Debug mode, open CORS, 0.0.0.0 binding |
| A06 | Vulnerable Components | `vuln_components.py` | Flagged packages in `requirements.txt` |
| A07 | Auth Failures | `auth_failures.py` | Plaintext password comparisons, hardcoded passwords |
| A08 | Data Integrity | `data_integrity.py` | Unsafe pickle/YAML deserialization |
| A09 | Logging Failures | `logging_monitoring.py` | Sensitive operations without logging |
| A10 | SSRF | `ssrf.py` | User input passed to outbound HTTP requests |

## 🏗️ Project Structure

```
SecureFlow/
├── main.py                              # CLI entry point
│
├── core/
│   ├── analyzer.py                      # Engine: parse → load plugins → collect findings
│   ├── taint_engine.py                  # Taint propagation from sources → sinks
│   └── cfg.py                           # Basic control-flow graph
│
├── analysis/
│   ├── auth_tracker.py                  # Inline authentication check detection
│   └── framework.py                     # Flask / FastAPI / Django detection
│
└── plugins/
    ├── base.py                          # BaseScannerPlugin interface
    ├── broken_access_control.py         # A01
    ├── crypto_failures.py               # A02
    ├── injection.py                     # A03
    ├── insecure_design.py               # A04
    ├── security_misconfig.py            # A05
    ├── vuln_components.py               # A06
    ├── auth_failures.py                 # A07
    ├── data_integrity.py                # A08
    ├── logging_monitoring.py            # A09
    └── ssrf.py                          # A10
```

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/swati-yelamanchili/SecureFlow.git
cd SecureFlow
```

### 2. Run the scanner

Scan a specific file:

```bash
python3 main.py app.py
```

Scan an entire directory:

```bash
python3 main.py /path/to/project
```

Scan the current directory:

```bash
python3 main.py
```

Disable colored output:

```bash
python3 main.py app.py --no-color
```

## 📊 Example Output

```
[HIGH]
  line 15 | Broken Access Control | Missing Access Control
    Issue : Route with database access lacks proper access control.
    Fix   : Add authentication/authorization checks.
  line 27 | Injection | SQL Injection
    Issue : Tainted input reaches dangerous sink: db.execute
    Fix   : Sanitize or parameterize inputs.

[MEDIUM]
  line 21 | Cryptographic Failures | Weak Hash Algorithm
    Issue : Usage of weak hash algorithm: hashlib.md5
    Fix   : Use strong algorithms like SHA-256 or bcrypt/Argon2.
  line 30 | Security Misconfiguration | Debug Mode Enabled
    Issue : Application runs with debug=True.
    Fix   : Disable debug mode in production.

[LOW]
  line 10 | Identification and Authentication Failures | Hardcoded Password
    Issue : Password stored in plaintext in variable 'password'.
    Fix   : Hash passwords with bcrypt or Argon2 before storage.
  line 42 | Security Logging and Monitoring Failures | Missing Logging
    Issue : Sensitive operation 'authenticate' does not implement logging.
    Fix   : Add logging to audit sensitive transactions.
```

## ⚙️ Requirements

- **Python 3.8+**

No external packages required — the scanner uses only the Python standard library.

## 🔧 How It Works

### 1. File Discovery
The scanner walks the target path and collects `.py` files, skipping common noise directories (`.git`, `__pycache__`, `venv`, `node_modules`, etc.).

### 2. AST Parsing
Each file is parsed into an abstract syntax tree, allowing inspection of assignments, function calls, decorators, and control flow without executing any code.

### 3. Taint Propagation
The taint engine marks variables assigned from user-controlled sources (`request.args`, `input()`, `os.getenv()`, etc.) and propagates taint through assignments, f-strings, concatenations, and function calls.

### 4. Plugin Execution
All plugins in the `plugins/` directory are auto-discovered and executed. Each plugin receives the parsed AST and shared context (imports, detected framework) to perform its analysis.

### 5. Findings Report
Results are deduplicated, classified by severity, and printed in a clean grouped format.

## 🔌 Writing a Custom Plugin

Create a new file in `plugins/` — it will be auto-loaded:

```python
# plugins/my_check.py
import ast
from plugins.base import BaseScannerPlugin

class MyCheckPlugin(BaseScannerPlugin):
    def scan(self, tree, context):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = self.get_full_name(node.func)
                if name == "dangerous_function":
                    self.scanner.add_finding(
                        node,
                        "Custom Category",
                        "Dangerous Call",
                        "This function is risky.",
                        "Use a safer alternative.",
                    )
```

## ⚠️ Scope & Limitations

SecureFlow is designed for **learning, demos, and early-stage code review**. It is not a replacement for full SAST tooling or manual security audits.

Current limitations:

- Python-only (JavaScript support planned via tree-sitter)
- No inter-file data flow analysis
- No framework-specific sanitization models
- Heuristic-based detection may produce false positives/negatives
- No auto-fix mode

## 📄 License

[MIT License](LICENSE)

---

<div align="center">
  <sub>Built by <a href="https://github.com/swati-yelamanchili">Swati Yelamanchili</a></sub>
</div>
