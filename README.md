# Python Security Scanner

AST-based static security scanner for Python projects and common config files.

This project analyzes Python source code without executing it. It tracks tainted input from common untrusted sources, follows propagation across assignments and function returns, and reports risky sinks with severity, remediation guidance, and flow context.

## Highlights

- Static analysis built on Python's `ast` module
- Taint tracking for request data, environment variables, `input()`, and `sys.argv`
- Flow-aware reporting that shows how untrusted data reaches a sink
- Severity-based output grouped into `HIGH`, `MEDIUM`, and `LOW`
- Config scanning for insecure debug and binding settings
- No third-party dependencies required for the scanner itself

## What It Detects

### Injection

- SQL injection
  - Detects untrusted input reaching database execution sinks such as `execute()` and `executemany()`
  - Prefers sink-aware detection to reduce false positives
- OS command injection
  - Detects tainted input in `os.system`, `os.popen`, and `subprocess` calls with `shell=True`
- LDAP injection
  - Detects tainted data reaching LDAP search-style sinks
- Cross-site scripting (XSS)
  - Detects tainted HTML-like strings that are assigned, returned, or printed

### File and Network Risks

- Path traversal / user-controlled file path
  - Flags tainted filesystem paths passed into file-opening sinks
  - Escalates severity when explicit traversal markers like `../` or `..\\` appear
- Server-Side Request Forgery (SSRF)
  - Flags tainted outbound request targets
  - Raises severity for obvious internal-address patterns such as `127.x.x.x`, `localhost`, and `192.168.x.x`

### Integrity and Deserialization

- Unsafe deserialization via `pickle.load` / `pickle.loads`
- Dynamic code execution via `eval` / `exec`
- Unsafe `yaml.load(...)` without a safe loader

### Cryptographic and Secret Handling Issues

- Hardcoded secrets
- Plaintext passwords
- Weak hashes such as `md5` and `sha1`

### Security Misconfiguration

- Debug mode enabled in code
- Services binding to `0.0.0.0`
- Debug and host exposure patterns in config files

## Taint Sources

The scanner treats data from these inputs as untrusted:

- Flask-style request data
  - `request.args`
  - `request.form`
  - `request.values`
  - `request.headers`
  - `request.cookies`
  - `request.json`
  - `request.files`
- Environment-based input
  - `os.getenv(...)`
  - `os.environ[...]`
  - `os.environ.get(...)`
- Command-line input
  - `sys.argv[...]`
- Interactive input
  - `input()`

## Example Output

The report is grouped by severity and includes the issue, fix guidance, origin, and data-flow chain when available.

```text
[HIGH]
  app.py:42 | Injection | SQL injection
    Issue : Tainted data reaches a database execution sink without parameterization.
    Fix   : Use parameterized queries and keep untrusted input out of raw SQL strings.
    Origin: `user_id`
    Flow  : user_id -> query -> execute()

[MEDIUM]
  views.py:18 | Path Traversal | User-controlled file path
    Issue : Tainted input is used to build a filesystem path.
    Fix   : Validate filenames against an allowlist and resolve paths safely before opening files.
```

## Project Structure

```text
security_scanner/
├── security_scanner.py   # Main scanner CLI
├── README.md             # Project documentation
├── .gitignore            # Git ignore rules
└── security/             # Local virtual environment (ignored in Git)
```

## Requirements

- Python 3.8+

The scanner itself uses only the Python standard library.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/security_scanner.git
cd security_scanner
```

### 2. Run the scanner

Scan the current directory:

```bash
python3 security_scanner.py
```

Scan a specific file:

```bash
python3 security_scanner.py app.py
```

Disable ANSI colors:

```bash
python3 security_scanner.py . --no-color
```

## How It Works

### 1. File discovery

The scanner walks the provided target path and inspects:

- Python files: `*.py`
- Config files: `.ini`, `.cfg`, `.conf`, `.yaml`, `.yml`, `.toml`, `.json`
- Named config files such as `.env` and Docker Compose files

It skips common noise directories such as:

- `.git`
- `__pycache__`
- `.pytest_cache`
- `.mypy_cache`
- `.venv`
- `venv`
- `env`
- `node_modules`
- `dist`
- `build`
- `security`

### 2. AST parsing

Each Python file is parsed into an abstract syntax tree. This allows the scanner to inspect assignments, function calls, literals, and control-flow-related nodes without executing application code.

### 3. Taint propagation

Tainted values are propagated through:

- direct assignment
- annotated assignment
- augmented assignment
- function returns
- nested expressions such as f-strings, concatenation, subscripts, containers, and conditional expressions

### 4. Sink validation

Findings are reported at meaningful sinks such as:

- database execution calls
- shell execution calls
- file-opening calls
- outbound HTTP requests
- LDAP search calls

This keeps the output closer to real risk and reduces noisy pattern matching.

### 5. Deduplication and sorting

The scanner collapses duplicate findings and sorts results by severity first, then by location for predictable output.

## Supported Severity Levels

- `HIGH`
  - confirmed dangerous sinks
  - explicit traversal patterns
  - unsafe deserialization and dynamic code execution
- `MEDIUM`
  - exploitable-looking but not fully confirmed misuse
  - XSS, generic SSRF, unsafe YAML loading, non-explicit user-controlled file paths
- `LOW`
  - weak crypto, hardcoded secrets, and risky debug settings

## Scope Limitations

This scanner is intentionally lightweight. It is useful for learning, demos, and early code review, but it is not a replacement for full SAST tooling or manual security review.

Current limitations include:

- Python-focused only
- Heuristic-based detection can still produce false positives or false negatives
- No inter-file dataflow engine
- No framework-specific sanitization model
- No autofix mode

## Categories Not Currently Covered

- Broken Access Control
- Insecure Design
- Vulnerable & Outdated Components
- Identification & Authentication Failures
- Security Logging & Monitoring Failures

## License

MIT License 
