# Architecture

This document describes the internal architecture of RRI (Recon Intelligence), including its core components, reconnaissance modules, data flow, security boundaries, and reporting pipeline.

## 1. Architectural Overview

RRI is a Python-based command-line reconnaissance tool.

Its architecture separates shared infrastructure from individual reconnaissance modules.

The main architectural layers are:

1. CLI and orchestration.
2. Core infrastructure.
3. Reconnaissance and analysis modules.
4. Correlation engine.
5. Reporting engine.

The core layer provides shared functionality such as scope validation, DNS resolution, HTTP communication, redirect validation, and report generation.

Reconnaissance modules analyze the collected responses and produce structured results.

The correlation engine identifies relationships between findings from different modules. It does not establish that a vulnerability is exploitable.

## 2. Project Structure

The current project structure is organized as follows:

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

### Main Entry Point

`main.py` provides:

- Argument parsing.
- CLI option handling.
- Target scope initialization.
- Scan orchestration.
- Result summarization.
- Report generation.
- Terminal output and error handling.

The CLI is the entry point for normal application execution.

## 3. Core Infrastructure

The `core/` package contains shared components used by the application and its modules.

### 3.1 Scope Engine

File: `core/scope.py`

The scope engine determines whether a URL belongs to the authorized assessment scope.

Its responsibilities include:

- Validating HTTP and HTTPS URLs.
- Normalizing hostnames.
- Applying hostname and path restrictions.
- Rejecting unsupported schemes and ports.
- Rejecting malformed or ambiguous URL forms.
- Supporting explicit scope configuration through the core component.

For normal CLI execution, the scope is derived from the target URL supplied with `-u`.

The default CLI scope authorizes the exact target hostname, without automatically including subdomains.

### 3.2 Network Safety

File: `core/network_safety.py`

This component provides IP address validation.

It uses Python's IP address handling to reject addresses that are not considered globally routable.

It also provides DNS result validation helpers.

This functionality contributes to the network safety model but does not replace the protections applied by the HTTP engine's resolver.

### 3.3 DNS Resolver

File: `core/dns_resolver.py`

`SafeDNSResolver` integrates with aiohttp's resolver interface.

Its responsibilities include:

- Resolving hostnames.
- Applying a DNS timeout.
- Validating returned address records.
- Rejecting non-global IP addresses.
- Validating address families and socket record properties.
- Rejecting an entire DNS answer if it contains an invalid or non-global address.

The HTTP engine uses this resolver for its network requests.

### 3.4 Redirect Guard

File: `core/redirect_guard.py`

The redirect guard validates HTTP redirect destinations before the HTTP engine follows them.

It checks:

- The current URL.
- The redirect destination.
- The redirect count.
- URL validity.
- Whether the destination remains within the authorized scope.

Redirects outside the authorized scope are blocked.

### 3.5 HTTP Engine

File: `core/http_engine.py`

`HTTPEngine` is the shared HTTP communication component.

Its responsibilities include:

- Creating asynchronous HTTP sessions.
- Applying connection and request timeouts.
- Using the safe DNS resolver.
- Enforcing response-size limits.
- Limiting response header sizes and counts.
- Disabling automatic redirect handling.
- Passing redirects through the redirect guard.
- Returning structured response data.

The engine checks the requested URL against the scope before creating a network session.

Automatic decompression is disabled, and the engine requests identity encoding. Response-size limits are enforced while reading the response body.

The HTTP engine is shared by the reconnaissance modules so that they use consistent communication and safety controls.

### 3.6 Correlation Engine

File: `core/correlation_engine.py`

The correlation engine analyzes relationships between results produced by different modules.

It currently supports relationships involving:

- API endpoints and security findings.
- API endpoints and header findings.
- API endpoints and technology evidence.

It applies same-origin validation before correlating results.

Correlation is evidence-based. A relationship between two observations does not prove that a vulnerability exists or is exploitable.

The engine also limits the number of generated correlations and the amount of evidence retained.

### 3.7 Reporting Engine

File: `core/reporting.py`

The reporting engine converts structured scan results into reports.

It supports:

- HTML reports.
- JSON reports.
- Both formats in one execution.

It handles output paths, timestamps, target-based filenames, report directories, and HTML escaping of dynamic content.

## 4. Reconnaissance Modules

The `modules/` package contains independent analysis components.

### 4.1 Technology Fingerprinting

File: `modules/technology.py`

The technology detector analyzes available HTTP headers, cookies, HTML metadata, markup, and inline JavaScript indicators.

It identifies possible technologies and assigns confidence levels based on accumulated evidence.

Detection is signature-based and heuristic. It does not guarantee that an identified technology is present or that the detected version is accurate.

### 4.2 API Discovery

File: `modules/api_discovery.py`

The API discovery module examines:

- HTML references.
- Inline JavaScript.
- Same-scope external JavaScript assets.

It extracts potential API endpoint references and documentation indicators.

The module has limits on the number of external scripts fetched and the number of endpoints recorded.

Important architectural boundary:

API discovery does not automatically send requests to discovered API endpoints.

It identifies references for later manual review rather than actively probing those endpoints.

### 4.3 HTTP Headers Analysis

File: `modules/headers_analysis.py`

This module analyzes HTTP response headers and cookie attributes.

It checks for the presence and selected configuration properties of security-related headers, as well as common cookie security attributes.

Its results are heuristic observations, not a complete assessment of the target's security posture.

### 4.4 Passive Security Checks

File: `modules/security_checks.py`

This module examines the retrieved response for potentially sensitive indicators, including:

- Administrative path references.
- Sensitive file references.
- Source map references.
- Debug and error information.
- Configuration-related indicators.
- Directory listing indicators.
- Internal path and address references.

It does not automatically visit discovered paths, download referenced source maps, or exploit identified indicators.

A reference in page content does not establish that the referenced resource is accessible.

## 5. Scan Data Flow

A normal scan follows this sequence:

1. The user supplies a target URL through the CLI.
2. `main.py` parses the command-line arguments.
3. The scope engine derives the default authorized scope from the target.
4. The target is checked against that scope.
5. The HTTP engine fetches the initial page.
6. If the initial request fails, the scan stops and reports the failure.
7. The reconnaissance modules analyze the initial response.
8. API discovery may fetch a limited number of authorized JavaScript assets.
9. Module results are passed to the correlation engine.
10. The CLI builds a summary of the results.
11. The reporting engine generates the requested output formats.

Conceptually:

    User
      |
      v
    CLI (main.py)
      |
      v
    Scope Validation
      |
      v
    HTTP Engine
      |
      v
    Initial HTTP Response
      |
      +-------------------+
      |         |         |
      v         v         v
    Technology  API      Headers
    Detection   Discovery Analysis
                  |
                  v
             Authorized JS
                Assets

      Passive Security Checks
                  |
                  v
           Module Results
                  |
                  v
          Correlation Engine
                  |
                  v
             CLI Summary
                  |
                  v
           Reporting Engine
                  |
             +----+----+
             |         |
             v         v
            HTML      JSON

This diagram represents the logical processing flow. Individual modules may analyze the same initial response independently.

## 6. Shared Response Model

The HTTP engine returns structured response information to its callers.

A successful response includes:

- Final response URL.
- HTTP status code.
- Response headers.
- Header items.
- Response body bytes.
- Redirect history.
- Error information.

Modules consume this response data and return their own structured results.

A module result generally includes a status, target, findings or detected items, counts, and error information where applicable.

The exact fields differ between modules.

## 7. Security Architecture

Security controls are applied across several layers rather than being delegated to individual reconnaissance modules.

### Scope Enforcement

The scope engine validates requested URLs and defines the authorized hostname and path boundaries.

### DNS Validation

The safe resolver validates resolved addresses and rejects non-global destinations.

### HTTP Request Controls

The HTTP engine applies timeouts, response-size limits, header limits, and controlled redirect handling.

### Redirect Validation

Redirect destinations are checked against the authorized scope before another request is made.

### Same-Origin Correlation

The correlation engine only relates evidence belonging to the same normalized origin.

### Passive Discovery Boundaries

Discovered API endpoints and sensitive resource references are not automatically probed by the discovery modules.

These controls reduce risk but should not be interpreted as a guarantee against every possible network or application-level attack.

See [Scope and Safety](SCOPE-AND-SAFETY.md) for the detailed security model.

## 8. Asynchronous Execution

RRI uses Python's asynchronous programming model for HTTP operations.

The HTTP engine is built on aiohttp, and scan orchestration is initiated through Python's asyncio runtime.

This allows asynchronous network operations while keeping the module interfaces organized around shared response data.

## 9. Testing Architecture

The `tests/` directory contains automated tests for core infrastructure, modules, CLI behavior, reporting, and security boundaries.

The test suite includes coverage for:

- Scope validation.
- HTTP behavior.
- DNS validation.
- Redirect handling.
- Technology detection.
- API discovery.
- Header analysis.
- Passive security checks.
- Correlation behavior.
- Report generation.
- CLI functionality.

Run the test suite with:

    .venv/bin/python -m unittest discover -s tests -v

See [Testing](TESTING.md) for testing procedures and coverage details.

## 10. Design Principles

The current architecture follows these principles:

- Separation of core infrastructure and reconnaissance modules.
- Shared HTTP communication and safety controls.
- Explicit target selection at runtime.
- Default-deny behavior for URLs outside the authorized scope.
- Bounded response processing and asset fetching.
- Structured module results.
- Evidence-based correlation.
- Separation of discovery from active probing.
- Multiple report formats.
- Automated testing of security-sensitive behavior.

## 11. Current Architectural Boundaries

The following limitations are important when interpreting the current implementation:

- Technology detection is signature-based and heuristic.
- API discovery identifies references but does not validate endpoint functionality.
- OpenAPI and Swagger references are indicators, not parsed API specifications.
- Header analysis does not implement a complete standards-compliance assessment.
- Passive security checks do not establish exploitability.
- Correlation identifies evidence relationships, not confirmed vulnerabilities.
- The CLI does not currently expose every capability available in the core components.

Future features should preserve the separation between discovery, validation, and active testing, and should not weaken the existing scope and network safety boundaries.

---

For command usage, see [CLI Reference](CLI.md).

For module-specific behavior, see [Recon Modules](RECON-MODULES.md).
