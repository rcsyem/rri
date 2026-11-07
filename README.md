# RRI — Recon Intelligence

**A security-focused reconnaissance CLI for discovering and analyzing web application technologies, API references, HTTP security configurations, and potential security indicators.**

RRI is a local command-line reconnaissance tool designed to help security researchers and authorized testers understand the externally observable characteristics of web applications.

It combines multiple reconnaissance modules with a correlation engine and generates structured HTML and JSON reports.

> **Project status:** Early development — version 0.1.0.

---

## Features

### 1. Technology Fingerprinting

Identifies technologies using observable indicators such as:

- HTTP response headers.
- Cookies.
- HTML metadata.
- HTML content.
- JavaScript and CSS references.
- Framework-specific indicators.

### 2. API Discovery

Identifies potential API endpoints and API-related references from:

- HTML content.
- Inline JavaScript.
- Same-scope JavaScript assets.
- Common REST and GraphQL patterns.
- OpenAPI and Swagger references.

RRI discovers references but does not automatically probe discovered API endpoints.

### 3. HTTP Headers Analysis

Examines HTTP security headers, including:

- Strict-Transport-Security (HSTS).
- Content-Security-Policy (CSP).
- X-Frame-Options.
- X-Content-Type-Options.
- Referrer-Policy.
- Permissions-Policy.
- Cross-Origin isolation headers.

It also checks observable cookie security attributes.

### 4. Passive Security Checks

Identifies potential security indicators in the retrieved page, including:

- Administrative path references.
- Sensitive file references.
- Source map references.
- Debug and error messages.
- Potential configuration and secret-related patterns.
- Directory listing indicators.
- Internal path and address references.

These findings are indicators requiring manual verification, not confirmed vulnerabilities.

### 5. Correlation Engine

Connects related evidence across reconnaissance modules, helping researchers identify relationships between:

- API endpoint references.
- Technology indicators.
- HTTP header findings.
- Passive security findings.

Correlations represent evidence overlap and do not establish exploitability.

### 6. Reporting

Generates reports in:

- HTML.
- JSON.
- Both formats.

Reports include module results, severity summaries, and correlation findings.

---

## Requirements

- Python 3.11 or later.
- pip.
- aiohttp 3.12 or later, below version 4.
- An operating system supported by Python and aiohttp.

RRI has been developed and tested in a Kali Linux environment.

---

## Installation

RRI recommends [pipx](https://pipx.pypa.io/) for installation. It creates an
isolated Python environment and makes the `rri` command available without
requiring manual virtual-environment activation.

### 1. Install pipx

On Kali Linux and Debian-based systems:

    sudo apt update
    sudo apt install pipx
    pipx ensurepath

Restart your terminal if necessary.

### 2. Install RRI

Clone the official repository:

    git clone https://github.com/rcsyem/rri.git
    cd rri

Install RRI:

    pipx install .

### 3. Verify the installation

    rri --version
    rri --help

The `rri` command should now be available from any directory.

### Alternative: Virtual Environment

Developers who prefer a traditional virtual environment can use:

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .

Then verify:

    rri --version

## Usage

Run a reconnaissance scan against an explicitly authorized target:

    rri -u https://example.com

### Command-line options

| Option | Description |
|---|---|
| `-u`, `--url` | Target URL (required). |
| `-f`, `--format` | Report format: `html`, `json`, or `both`. Default: `html`. |
| `-o`, `--output` | Custom report output path. |
| `-V`, `--version` | Display the installed version. |
| `--no-color` | Disable colored terminal output. |
| `-h`, `--help` | Display command help. |

### Generate an HTML report

    rri -u https://example.com -f html

### Generate a JSON report

    rri -u https://example.com -f json

### Generate both HTML and JSON reports

    rri -u https://example.com -f both

### Specify an output path

    rri -u https://example.com -f both -o reports/example

When using `both`, RRI generates separate `.html` and `.json` files using the supplied output path as the base name.

---

## Scope and Safety

RRI is designed with a restrictive authorization model.

### Default Scope Behavior

When a target is supplied through `-u`, RRI derives its default authorized scope from that target URL.

By default:

- Only the exact target hostname is authorized.
- Subdomains are not automatically authorized.
- All paths on the authorized hostname are permitted.
- URLs outside the authorized scope are blocked.

### Network Safety

The HTTP engine includes safeguards for:

- DNS resolution and public IP validation.
- Private and non-public IP address rejection.
- Redirect scope validation.
- URL and hostname validation.
- Response-size limits.
- HTTP header limits.
- Request timeouts.

### Passive Discovery

RRI does not automatically send requests to discovered API endpoints, sensitive paths, or referenced administrative locations.

JavaScript assets may be fetched only when they are within the authorized scope and within the configured discovery limit.

**Important:** Use RRI only against systems you own or have explicit permission to assess. You are responsible for ensuring that your testing complies with applicable laws and authorization agreements.

See [Scope and Safety](docs/SCOPE-AND-SAFETY.md) for details.

---

## Architecture

RRI is organized into core infrastructure and reconnaissance modules.

    rri/
    ├── core/
    │   ├── scope.py
    │   ├── network_safety.py
    │   ├── dns_resolver.py
    │   ├── redirect_guard.py
    │   ├── http_engine.py
    │   ├── correlation_engine.py
    │   └── reporting.py
    │
    ├── modules/
    │   ├── technology.py
    │   ├── api_discovery.py
    │   ├── headers_analysis.py
    │   └── security_checks.py
    │
    ├── tests/
    ├── reports/
    ├── config/
    ├── main.py
    ├── pyproject.toml
    └── requirements.txt

The core layer provides scope enforcement, safe network access, redirect validation, correlation, and report generation.

The modules perform individual reconnaissance tasks and return structured results.

See [Architecture](docs/ARCHITECTURE.md) for more information.

---

## Testing

RRI includes automated tests covering:

- Scope validation.
- HTTP behavior.
- DNS safety.
- Redirect handling.
- Technology detection.
- API discovery.
- HTTP headers analysis.
- Passive security checks.
- Correlation.
- Report generation.
- CLI behavior.

Run the test suite from the project directory:

    .venv/bin/python -m unittest discover -s tests -v

---

## Documentation

| Document | Description |
|---|---|
| [Installation](docs/INSTALLATION.md) | Installation and environment setup. |
| [CLI Reference](docs/CLI.md) | Command-line usage and options. |
| [Architecture](docs/ARCHITECTURE.md) | Internal architecture and components. |
| [Recon Modules](docs/RECON-MODULES.md) | Detailed module documentation. |
| [Scope and Safety](docs/SCOPE-AND-SAFETY.md) | Authorization and network safeguards. |
| [Reporting](docs/REPORTING.md) | HTML and JSON reports. |
| [Testing](docs/TESTING.md) | Automated testing. |
| [Development](docs/DEVELOPMENT.md) | Development and contribution guidance. |
| [Arabic Documentation](README.ar.md) | Arabic user documentation. |

The documentation set is available in the `docs/` directory.

---

## License

RRI is released under the **MIT License**. See the [LICENSE](LICENSE) file
for the complete license terms.

---

## Disclaimer

RRI is a reconnaissance and analysis tool. Its findings are based on observable evidence and heuristic detection.

A finding does not necessarily indicate a vulnerability, and the absence of findings does not guarantee that a target is secure.

Always manually verify results and obtain authorization before testing any system.
