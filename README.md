# 🔒 SecureFlow

A lightweight static security scanner for Python that detects common vulnerabilities using AST-based taint tracking and data flow analysis.

---

## 🚀 Features

* **AST-based analysis** (no runtime required)
* **Taint tracking**

  * Tracks untrusted input from sources like:

    * `request.args`, `request.form`
    * `input()`
    * `os.getenv`, `os.environ`
* **Data flow analysis**

  * Tracks how data propagates across variables and functions
  * Reconstructs flow: `source → intermediate → sink`
* **Grouped vulnerability reporting**

  * Groups multiple sinks under a single origin
* **Severity classification**

  * HIGH / MEDIUM / LOW
* **Clean CLI output with optional colors**

---

## 🛡️ Detected Vulnerabilities

### Injection

* SQL Injection (with sink validation)
* OS Command Injection
* LDAP Injection
* Cross-Site Scripting (XSS)

### File & System

* Path Traversal (severity-aware)

### Network

* Server-Side Request Forgery (SSRF)

### Security Misconfiguration

* Debug mode enabled
* Exposed service binding (`0.0.0.0`)

### Cryptographic Issues

* Hardcoded secrets
* Plaintext passwords
* Weak hash usage (MD5, SHA1)

### Data Integrity

* Unsafe deserialization (`pickle`)
* Unsafe YAML loading
* Dynamic code execution (`eval`, `exec`)

---

## 🧠 How It Works

1. Parses Python code into an AST
2. Identifies **taint sources** (user-controlled input)
3. Propagates taint across assignments and function returns
4. Detects when tainted data reaches **dangerous sinks**
5. Reports:

   * vulnerability type
   * severity
   * origin variable
   * affected lines
   * data flow

---

## ⚙️ Installation

```bash
git clone https://github.com/your-username/secureflow.git
cd secureflow
```

No external dependencies required (pure Python).

---

## ▶️ Usage

Scan a file:

```bash
python security_scanner.py test_code.py
```

Scan a directory:

```bash
python security_scanner.py .
```

Disable colored output:

```bash
python security_scanner.py . --no-color
```

---

## 📄 Example Output

```text
[HIGH]
  test_code.py | Injection | SQL injection (Origin: `id`)
    Issue : Tainted data reaches a database execution sink without parameterization.
    Fix   : Use parameterized queries and keep untrusted input out of raw SQL strings.
    Sinks :
      - line 78
      - line 79
    Flow  : id → execute()

[MEDIUM]
  test_code.py:38 | Path Traversal | User-controlled file path
    Issue : Tainted input is used to build a filesystem path.
    Fix   : Validate filenames against an allowlist and resolve paths safely before opening files.
    Origin: `filename`
    Flow  : filename → open()
```

---

## 📂 Project Structure

```text
secureflow/
│── security_scanner.py
│── test_code.py
│── README.md
```

---

## ⚠️ Limitations

* Static analysis only (no runtime execution)
* Limited framework awareness (basic Flask support)
* Does not detect:

  * Broken Access Control
  * Authentication flaws
  * Business logic issues

---

## 🔮 Future Improvements

* Framework-specific rules (Flask, Django)
* Better SQL query context detection
* Multi-language support
* CLI enhancements and reporting formats (JSON, HTML)

---

## 🎯 Why This Project

This project demonstrates how real security tools work internally using:

* AST parsing
* taint propagation
* source → sink analysis

instead of simple pattern matching.

---

## 📜 License

MIT License
