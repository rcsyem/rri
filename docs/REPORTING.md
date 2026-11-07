# Reporting

This document explains how RRI generates, stores, and structures reconnaissance reports.

RRI currently supports HTML, JSON, and combined report output.

## 1. Supported Formats

The report generator supports three formats:

| Format | Description |
|---|---|
| `html` | Generates a readable HTML report. |
| `json` | Generates structured JSON data. |
| `both` | Generates both HTML and JSON reports. |

The CLI uses HTML as its default format.

## 2. Generating Reports

Use the `-f` or `--format` option to select a report format.

### HTML

    rri -u https://example.com -f html

### JSON

    rri -u https://example.com -f json

### Both Formats

    rri -u https://example.com -f both

The target must still satisfy the normal scope and safety checks.

## 3. Selecting an Output Path

Use `-o` or `--output` to specify an output path.

Example:

    rri -u https://example.com -f html -o reports/example.html

For JSON:

    rri -u https://example.com -f json -o reports/example.json

When `both` is selected, the generator uses the supplied output path as a base and creates files with `.html` and `.json` extensions.

For example:

    rri -u https://example.com -f both -o reports/example

Produces:

- `reports/example.html`
- `reports/example.json`

If the output path has no extension and only one format is selected, the appropriate extension is added.

If a path with an extension is supplied for a single format, the generator uses that path as provided. It does not automatically correct a mismatched extension.

## 4. Default Report Location

When no output path is supplied, reports are written to the project's `reports/` directory.

The generated filename follows this general pattern:

    rri_<target>_<timestamp>.<format>

The target component is derived from the target hostname and converted into a filesystem-friendly slug.

The timestamp uses UTC in this format:

    YYYYMMDDTHHMMSSZ

Example filename:

    rri_example.com_20261103T120000Z.html

The actual timestamp and filename depend on the scan time and target.

## 5. HTML Report Contents

The HTML report is designed for convenient human review.

Its sections include:

1. Overview.
2. Severity summary.
3. Detected technologies.
4. Discovered API endpoints.
5. HTTP header findings.
6. Passive security checks.
7. Correlations between findings.

The report uses a responsive layout and a dark visual theme.

Dynamic content is HTML-escaped before being inserted into the report.

The HTML report also explains that findings are passive indicators and may require manual verification.

## 6. JSON Report Structure

The JSON report is intended for programmatic processing and integration with other tools.

The top-level structure contains:

| Field | Description |
|---|---|
| `tool` | Tool identification. |
| `generated_at` | Report generation time in UTC. |
| `target` | Scan target supplied to the report generator. |
| `results` | Results returned by the scan modules. |

The `results` object contains the module output, including available technology, API discovery, header analysis, security check, and correlation data.

The JSON output uses UTF-8-compatible text serialization and indentation for readability.

Values that are not directly JSON-serializable are converted using the generator's configured string fallback.

## 7. Severity Summary

The report generator summarizes findings using these severity levels:

- Critical
- High
- Medium
- Low
- Info

Severity counts are collected from:

- HTTP header analysis findings.
- Passive security check findings.
- Correlation results.

The summary reflects the severity values present in the module output.

It does not independently determine whether a finding is exploitable.

## 8. Understanding Reported Findings

Reports combine different types of reconnaissance evidence.

### Technology Fingerprinting

Detected technologies are based on response headers, cookies, HTML, metadata, and other observed indicators.

A technology match is not always definitive.

### API Discovery

Discovered endpoints are extracted from page and JavaScript references.

An endpoint appearing in the report does not prove that it is accessible or vulnerable.

### Header Analysis

Header findings describe missing, weak, or potentially misconfigured security headers.

They do not constitute a complete security assessment of the application's security policy.

### Passive Security Checks

Security checks identify suspicious references and response patterns.

A reference to a sensitive file or administrative path does not prove that the resource is accessible.

### Correlations

Correlations connect overlapping evidence from different modules.

An evidence relationship is not proof of a vulnerability or an exploitable attack path.

## 9. Report Integrity and Interpretation

Reports should be interpreted as records of observations made during a particular scan.

Consider the following when reviewing them:

- The target may change after the scan.
- Server responses may differ between requests.
- Technology indicators may be incomplete or misleading.
- Passive checks cannot confirm every security condition.
- Severity labels are heuristic classifications.
- Correlations require manual interpretation.
- Findings should be independently verified before being treated as confirmed vulnerabilities.

Do not use an RRI report alone as proof of compromise or as a substitute for a professional security assessment.

## 10. Output Directories and File Handling

The report generator creates required parent directories when necessary.

The default report directory is `reports/`.

Custom output paths can be used to organize reports by project or assessment.

The generator does not provide a report database, automatic report synchronization, or a built-in report comparison system.

Be careful when reusing an existing output filename because writing a report to an existing path can replace its contents.

## 11. Current Limitations

The current reporting implementation has several limitations:

- HTML reports are generated in English.
- Reports are generated locally.
- There is no built-in report upload or cloud synchronization.
- There is no built-in historical comparison or trend analysis.
- Correlation evidence is presented as analysis output, not as a confirmed attack chain.
- The generator does not independently validate the accuracy of module findings.
- A custom output extension is not automatically corrected when a single format is selected.

These limitations describe the current implementation and should not be interpreted as permanent design restrictions.

## 12. Developer Reference

The report generator is implemented in:

    core/reporting.py

The CLI integration is implemented in:

    main.py

The report generator exposes the supported formats through its `FORMATS` definition and creates reports through its `generate()` method.

When extending reporting functionality:

1. Preserve the existing JSON structure unless a deliberate schema change is documented.
2. Escape dynamic HTML content.
3. Keep report output deterministic where practical.
4. Handle filesystem errors.
5. Avoid exposing secrets or sensitive response values.
6. Add tests for new report fields and output behavior.

## 13. Related Documentation

- [CLI Reference](CLI.md)
- [Architecture](ARCHITECTURE.md)
- [Recon Modules](RECON-MODULES.md)
- [Scope and Safety](SCOPE-AND-SAFETY.md)
- [Testing](TESTING.md)
