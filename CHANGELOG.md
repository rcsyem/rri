# Changelog

All notable changes to RRI (Recon Intelligence) are documented in this file.

The project follows a version-based release history.

## [0.1.0] - Initial Development Release

### Added

- Python command-line interface.
- Runtime target selection through `-u` / `--url`.
- Runtime-derived hostname scope.
- Default denial of unauthorized subdomains.
- URL and path validation.
- Network safety and IP address validation.
- Asynchronous DNS resolver with address validation.
- Shared asynchronous HTTP engine.
- TLS configuration and bounded request handling.
- Manual redirect handling with scope validation.
- Technology fingerprinting.
- Passive API endpoint discovery.
- Limited same-scope JavaScript asset retrieval.
- HTTP security header analysis.
- Passive security checks.
- Evidence correlation between reconnaissance modules.
- HTML report generation.
- JSON report generation.
- Combined HTML and JSON report output.
- CLI summary and terminal output.
- Unit, integration, and security regression tests.

### Security

- Fail-closed behavior for unauthorized targets.
- Subdomains excluded from the default runtime scope.
- Non-global DNS destinations rejected.
- Redirect destinations checked against the authorized scope.
- Duplicate redirect Location headers rejected.
- HTTP response and header limits.
- API discovery separated from active endpoint probing.
- Sensitive paths and source map references reported without automatically visiting them.

### Documentation

- English project README.
- Arabic project README.
- Installation guide.
- CLI reference.
- Architecture documentation.
- Reconnaissance modules documentation.
- Scope and safety documentation.
- Reporting documentation.
- Testing guide.
- Development guide.

### Known Limitations

- The CLI does not currently expose custom scope configuration.
- API discovery does not actively test discovered endpoints.
- HTML reports are generated in English.
- Findings are heuristic observations and require manual verification.
- No built-in report database or cloud synchronization.
- No historical report comparison system.

---

## Versioning Notes

This changelog records implemented functionality and known limitations at the time of the documented release.

Future releases should add dated sections describing user-visible changes, security fixes, compatibility changes, and new functionality.

Do not list planned functionality under an implemented release until it is actually available.
