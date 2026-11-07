# Development Guide

This document explains how to work on the RRI codebase, understand its structure, add functionality, and preserve its security model.

It is intended for contributors and developers maintaining RRI.

## 1. Project Overview

RRI (Recon Intelligence) is a Python command-line reconnaissance tool.

Its architecture separates:

- Core scope and network safety.
- HTTP communication.
- Reconnaissance modules.
- Evidence correlation.
- Report generation.
- CLI orchestration.

The project is designed to keep network access controlled and make individual components testable.

## 2. Development Requirements

The project requires:

- Python 3.11 or later.
- aiohttp 3.x.
- A virtual environment for isolated dependencies.

The current project environment has been developed and tested with Python 3.13.

Use the project virtual environment:

    cd /root/rri

    .venv/bin/python

Do not assume that the system-wide Python interpreter is the same as the project's interpreter.

## 3. Install the Project for Development

Create a virtual environment if one does not already exist:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install the project in editable mode:

    python -m pip install -e .

Editable installation allows Python changes in the project source tree to be used without reinstalling the package after every source edit.

The project metadata and dependencies are defined in:

- `pyproject.toml`
- `requirements.txt`

The CLI entry point is declared in `pyproject.toml`:

    rri = "main:main"

## 4. Project Structure

The main source layout is:

    rri/
    ├── core/
    ├── modules/
    ├── tests/
    ├── reports/
    ├── config/
    ├── main.py
    ├── pyproject.toml
    └── requirements.txt

### Core

The `core/` package contains shared infrastructure:

| File | Responsibility |
|---|---|
| `scope.py` | Target and path authorization checks |
| `network_safety.py` | IP address safety validation |
| `dns_resolver.py` | Safe asynchronous DNS resolution |
| `redirect_guard.py` | Redirect destination validation |
| `http_engine.py` | Controlled asynchronous HTTP requests |
| `correlation_engine.py` | Relationships between module evidence |
| `reporting.py` | HTML and JSON report generation |

### Modules

The `modules/` package contains reconnaissance functionality:

| File | Responsibility |
|---|---|
| `technology.py` | Technology fingerprinting |
| `api_discovery.py` | API reference discovery |
| `headers_analysis.py` | HTTP security header analysis |
| `security_checks.py` | Passive security indicators |

### Tests

The `tests/` directory contains unit, integration, and security regression tests.

### Reports

The `reports/` directory is the default destination for generated reports.

### Configuration

The `config/` directory contains configuration files used by supported core functionality.

The current CLI derives its default target scope from the URL supplied at runtime. It does not expose a CLI option for loading a custom scope configuration.

## 5. Application Execution Flow

The CLI entry point is `main.py`.

The normal execution flow is:

1. Parse command-line arguments.
2. Validate the supplied target URL.
3. Create a runtime scope from the target.
4. Check that the initial target is authorized.
5. Create the shared HTTP engine.
6. Fetch the initial page.
7. Pass the initial response to reconnaissance modules.
8. Allow API Discovery to retrieve a limited number of authorized JavaScript assets.
9. Run evidence correlation.
10. Build the scan summary.
11. Generate the requested report format.

The scan orchestrator is responsible for coordinating the modules.

Modules should not independently redefine the overall scan workflow.

## 6. Shared HTTP Engine

Network-enabled modules should use:

    core/http_engine.py

The shared HTTP engine provides:

- Scope validation.
- Safe DNS resolution.
- TLS configuration.
- Request timeouts.
- Response-size limits.
- Header limits.
- Redirect validation.
- Structured response results.

Avoid creating independent unrestricted HTTP clients inside reconnaissance modules.

A module that bypasses the shared engine may also bypass important scope and network safety controls.

Any proposed exception must be reviewed as a security-sensitive architectural change.

## 7. Adding a Reconnaissance Module

A new module should have a clear and limited responsibility.

A recommended development process is:

1. Define the module's purpose.
2. Identify its required input data.
3. Decide whether it needs network access.
4. Reuse the shared HTTP engine if network access is necessary.
5. Apply scope checks to every requested destination.
6. Bound response processing and resource consumption.
7. Return a predictable result structure.
8. Add unit and security regression tests.
9. Integrate the module through the scan orchestrator.
10. Update the relevant documentation.

A module should not silently expand the authorized target scope.

## 8. Module Result Design

Modules should return structured dictionaries that clearly describe their execution state.

The existing modules generally use fields such as:

- `status`
- `target`
- `count`
- Module-specific result collections.
- `error`

Use consistent status handling and avoid returning ambiguous partial results as successful results.

When a module cannot complete its operation, its result should clearly indicate that condition.

Do not treat an empty findings list as proof that the target has no security issues.

## 9. Passive Reconnaissance Boundaries

The current workflow separates discovery from active testing.

Examples:

- API references may be identified without requesting the discovered endpoints.
- Sensitive paths may be reported without visiting them.
- Source map references may be identified without downloading the source maps.
- Configuration indicators may be reported without attempting to use the associated values.

New functionality must preserve these boundaries unless a separately authorized active-testing feature is deliberately designed, documented, and reviewed.

## 10. Scope and Network Safety Requirements

Security-sensitive code must preserve the existing scope model.

Important requirements include:

- Validate target URLs.
- Reject unauthorized hostnames.
- Do not automatically include subdomains.
- Validate paths where applicable.
- Use safe DNS resolution.
- Reject non-global network destinations.
- Validate redirect destinations.
- Apply finite timeouts.
- Bound response sizes.
- Avoid unrestricted environment proxy inheritance.
- Fail closed when required authorization checks fail.

Read [Scope and Safety](SCOPE-AND-SAFETY.md) before changing network-related code.

## 11. Testing Changes

Every meaningful behavior change should include appropriate tests.

Run the complete suite:

    .venv/bin/python -m unittest discover -s tests -v

Run the syntax compilation check:

    .venv/bin/python -m compileall -q core modules tests main.py

Security-sensitive changes should include negative tests for unauthorized or malformed inputs.

Use local test services, injected dependencies, and reserved test hostnames.

Do not use real third-party websites as routine test targets.

See [Testing](TESTING.md) for test organization and coverage details.

## 12. Code Quality Guidelines

When modifying the codebase:

- Keep responsibilities separated.
- Prefer small, focused components.
- Validate external input.
- Use explicit error handling.
- Avoid unnecessary dependencies.
- Keep network operations asynchronous where appropriate.
- Apply resource limits to external data.
- Avoid logging secrets or sensitive values.
- Preserve existing public interfaces unless a change is intentional.
- Document behavior that affects users or contributors.

Do not weaken security checks merely to make a test pass.

## 13. Dependency Management

Dependencies are declared in the project metadata and requirements file.

Before adding a dependency:

1. Confirm that the functionality cannot reasonably be implemented with existing dependencies or the Python standard library.
2. Review the dependency's maintenance and security posture.
3. Consider its compatibility with supported Python versions.
4. Keep the dependency requirement appropriately constrained.
5. Document why it is needed.
6. Add tests for the functionality that uses it.

Avoid introducing large frameworks for narrowly scoped functionality.

## 14. Documentation Maintenance

Update documentation whenever a change affects:

- CLI arguments or behavior.
- Installation requirements.
- Scope rules.
- Network safety controls.
- Module behavior.
- Report structure.
- Test procedures.
- Developer workflows.

Keep the English documentation as the primary technical reference.

The Arabic README is intended to make the project easier to understand for Arabic-speaking users.

Do not document planned functionality as though it already exists.

## 15. Security Review Checklist

Before accepting a security-sensitive change, review:

- Does it preserve the runtime authorization scope?
- Can it contact an unauthorized hostname?
- Can it follow an external redirect?
- Can DNS resolution lead to a non-global destination?
- Are timeouts and response limits enforced?
- Can untrusted input cause excessive resource consumption?
- Does it expose credentials or sensitive response data?
- Are failures handled safely?
- Are negative regression tests included?
- Does the documentation accurately describe the behavior?

A passing test suite is necessary but not sufficient for security approval.

## 16. Related Documentation

- [Installation](INSTALLATION.md)
- [CLI Reference](CLI.md)
- [Architecture](ARCHITECTURE.md)
- [Recon Modules](RECON-MODULES.md)
- [Scope and Safety](SCOPE-AND-SAFETY.md)
- [Reporting](REPORTING.md)
- [Testing](TESTING.md)
