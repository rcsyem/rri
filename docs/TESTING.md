# Testing

This document describes how to run the RRI test suite, understand its coverage, and validate changes safely.

RRI uses Python's built-in `unittest` framework.

## 1. Testing Goals

The test suite is intended to verify:

- Core URL and scope validation.
- Network safety behavior.
- DNS response validation.
- HTTP request handling.
- Redirect authorization.
- Reconnaissance module behavior.
- Evidence correlation.
- Report generation.
- CLI behavior.
- Fail-closed handling of invalid or unauthorized inputs.

Tests help detect regressions but do not prove that the application is free of defects.

## 2. Environment

The project uses:

- Python 3.11 or later.
- aiohttp 3.x.
- Python's built-in `unittest` framework.

The development environment used for the current project includes Python 3.13.

Use the project's virtual environment when running commands:

    cd /root/rri

    .venv/bin/python

Do not assume that the system-wide `python` command points to the correct interpreter.

## 3. Run the Complete Test Suite

Run all discovered tests with:

    .venv/bin/python -m unittest discover -s tests -v

This command discovers test modules under `tests/` and executes the available test cases.

The verbose option displays individual test results.

For a shorter summary, use:

    .venv/bin/python -m unittest discover -s tests

A successful run ends with an `OK` result.

If a test fails, inspect the failure details before changing implementation code.

## 4. Compile-Time Syntax Check

Run:

    .venv/bin/python -m compileall -q core modules tests main.py

This checks Python source files for compilation errors.

A successful command normally produces no output.

Compilation does not execute the application and does not replace the test suite.

## 5. Test Organization

Tests are grouped by component and behavior.

| Test file | Main coverage |
|---|---|
| `test_core.py` | Core validation and safety behavior |
| `test_http_integration.py` | HTTP engine integration |
| `test_http_hardening.py` | HTTP configuration and redirect handling |
| `test_tls_integration.py` | TLS integration behavior |
| `test_technology.py` | Technology fingerprinting |
| `test_api_discovery.py` | API discovery behavior |
| `test_headers_analysis.py` | HTTP security header analysis |
| `test_header_items.py` | Header item handling |
| `test_security_checks.py` | Passive security checks |
| `test_correlation_engine.py` | Evidence correlation |
| `test_correlation_origin.py` | Same-origin correlation rules |
| `test_reporting.py` | HTML and JSON report generation |
| `test_cli.py` | CLI helpers and terminal behavior |
| `test_scope_hardening.py` | Scope validation hardening |
| `test_redirect_guard_hardening.py` | Redirect validation hardening |
| `test_dns_resolver_hardening.py` | DNS resolver validation hardening |

The exact number of tests may change as the project evolves.

## 6. Security Test Areas

### Scope Validation

Tests cover:

- Valid HTTP and HTTPS targets.
- Unsupported schemes and ports.
- URL credentials.
- Invalid hostname forms.
- Hostname suffix attacks.
- Subdomain restrictions.
- Path validation.
- Empty-scope fail-closed behavior.
- Runtime target-derived scope.

### DNS Resolver

Tests cover:

- Public IPv4 and IPv6 results.
- Invalid address records.
- Non-global addresses.
- Invalid address families.
- Invalid socket protocol values.
- Invalid resolver inputs.
- Resolver timeout and lookup validation.

### HTTP Engine

Tests cover:

- Invalid constructor parameters.
- Scope checks before network requests.
- Response handling.
- Redirect processing.
- Header constraints.
- Response-size limits.
- Network failure behavior.

### Redirect Guard

Tests cover:

- Relative redirects.
- Parent-relative redirects.
- Query redirects.
- External destinations.
- Protocol-relative destinations.
- Similar but unauthorized hostnames.
- Scheme changes.
- Credentials in redirect URLs.
- Malformed and oversized Location values.
- Redirect count limits.

### Same-Origin Correlation

Tests verify that evidence from different origins is not incorrectly correlated as same-origin evidence.

## 7. Local Test Safety

Tests should use controlled test inputs and local test services.

The project test strategy uses reserved `.invalid` hostnames and loopback addresses where appropriate.

Do not replace these test targets with real third-party websites.

Do not run a real reconnaissance scan merely to verify that the test suite works.

A test that needs network behavior should use a controlled local test server or an injected test dependency.

## 8. Interpreting Test Results

A passing test suite means that the tested cases passed under the environment in which they were executed.

It does not establish that:

- Every possible URL input has been tested.
- Every DNS or network environment behaves identically.
- Every website response can be parsed correctly.
- Every technology fingerprint is accurate.
- Every security finding is exploitable.
- Every future module automatically follows the safety model.
- The tool is immune to all network or application security risks.

Tests should be expanded when new functionality or security-sensitive behavior is introduced.

## 9. Test Maintenance

When modifying the project:

1. Add tests for new behavior.
2. Add negative tests for invalid inputs.
3. Test unauthorized destinations.
4. Test boundary values and resource limits.
5. Preserve existing security tests.
6. Run the complete suite after related changes.
7. Run the compile-time syntax check.
8. Review failures instead of weakening assertions merely to obtain a passing result.

Security-sensitive changes should include regression tests demonstrating that previously blocked behavior remains blocked.

## 10. Known Test Execution Considerations

Some test files contain a `unittest.main()` entry point before later test classes are declared.

When such a file is executed directly, classes declared after that entry point may not be included in that direct run.

The complete discovery command in this document imports the test modules and discovers their test classes.

Use complete test discovery as the primary validation command.

This test-file organization can be improved in a future maintenance change by moving direct-execution entry points to the end of their files.

## 11. Recorded Test Baseline

The latest recorded full-suite result during the current development and documentation review was:

    Ran 242 tests in 4.887s

    OK

The compile-time syntax check also completed successfully.

This is a historical development checkpoint, not a claim that every later code change has already been tested.

Re-run the complete suite against the current working tree before publishing a release.

## 12. Related Documentation

- [Installation](INSTALLATION.md)
- [Development Guide](DEVELOPMENT.md)
- [Architecture](ARCHITECTURE.md)
- [Scope and Safety](SCOPE-AND-SAFETY.md)
- [CLI Reference](CLI.md)
