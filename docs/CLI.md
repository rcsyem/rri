# Command-Line Interface Reference

This document describes the currently implemented command-line interface (CLI) of RRI (Recon Intelligence).

## 1. Overview

RRI is operated through the `rri` command.

The target URL must be supplied explicitly when starting a scan.

Basic syntax:

    rri -u <TARGET_URL>

Example:

    rri -u https://example.com

Only scan systems that you own or have explicit authorization to assess.

## 2. Available Options

The following options are currently implemented:

| Option | Description |
|---|---|
| `-u`, `--url` | Target URL. Required when running a scan. |
| `-f`, `--format` | Report format: `html`, `json`, or `both`. Default: `html`. |
| `-o`, `--output` | Custom output path for generated reports. |
| `-V`, `--version` | Display the installed RRI version. |
| `--no-color` | Disable colored terminal output. |
| `-h`, `--help` | Display command-line help. |

## 3. Target URL

Use `-u` or `--url` to specify the target.

Example:

    rri -u https://example.com

The target is supplied at runtime. RRI derives its default authorized scope from the target URL.

By default:

- The exact hostname supplied by the user is authorized.
- Subdomains are not included.
- Paths on the authorized hostname are included by default.
- The current CLI does not expose an option to load a custom scope configuration file or add additional authorized hostnames.

The scope configuration capability available in the core scope component is not currently exposed as a CLI option.

See [Scope and Safety](SCOPE-AND-SAFETY.md) for details.

## 4. Report Format

Use `-f` or `--format` to select the report format.

### HTML

HTML is the default format.

    rri -u https://example.com

You can also select it explicitly:

    rri -u https://example.com -f html

### JSON

Generate a JSON report:

    rri -u https://example.com -f json

JSON reports contain structured scan results, including the target, generation timestamp, tool information, and module results.

### Both Formats

Generate HTML and JSON reports in the same run:

    rri -u https://example.com -f both

This creates two separate report files.

## 5. Custom Output Path

Use `-o` or `--output` to specify a custom report path.

Example:

    rri -u https://example.com -f html -o reports/example

If the output path does not include a file extension, RRI adds the extension corresponding to the selected format.

For a single format, an explicitly supplied extension is retained as provided.

When using `both`, RRI generates two files using the supplied path as the base name:

- `reports/example.html`
- `reports/example.json`

RRI creates the required parent directories when generating reports.

If no custom output path is provided, reports are written to the default reports directory using a filename containing the target hostname and a UTC timestamp.

## 6. Version Information

Display the installed version:

    rri --version

Short form:

    rri -V

## 7. Help

Display the available command-line options:

    rri --help

The help output describes the options supported by the installed version.

## 8. Terminal Colors

RRI uses colored terminal output when standard output is connected to a terminal.

Color output is disabled when:

- `--no-color` is supplied.
- The `NO_COLOR` environment variable is present.
- Standard output is not detected as an interactive terminal.

Disable colors explicitly:

    rri -u https://example.com --no-color

## 9. Scan Execution

A scan follows this general sequence:

1. Parse and validate the command-line arguments.
2. Create the default scope from the supplied target URL.
3. Verify that the target is within the authorized scope.
4. Fetch the initial target page.
5. Run the implemented reconnaissance and analysis modules.
6. Correlate findings from the available modules.
7. Build a summary of the results.
8. Generate the requested report format or formats.

The implemented modules include:

- Technology Fingerprinting.
- API Discovery.
- HTTP Headers Analysis.
- Passive Security Checks.
- Correlation Analysis.

API discovery does not automatically send requests to discovered API endpoints. Same-scope JavaScript assets may be fetched within the configured limits.

See [Recon Modules](RECON-MODULES.md) for module behavior and limitations.

## 10. Exit Behavior

RRI returns a non-zero exit status when argument validation, target authorization, scanning, or report generation fails.

Examples of failure conditions include:

- An invalid or unauthorized target URL.
- A failed initial scan.
- An error while generating a report.
- Invalid command-line arguments.

A successful run completes report generation and displays the resulting report paths.

## 11. Common Usage Examples

### Basic scan

    rri -u https://example.com

### Scan and generate HTML

    rri -u https://example.com -f html

### Scan and generate JSON

    rri -u https://example.com -f json

### Generate both report formats

    rri -u https://example.com -f both

### Use a custom output path

    rri -u https://example.com -f both -o reports/example

### Disable terminal colors

    rri -u https://example.com --no-color

### Display version

    rri --version

### Display help

    rri --help

## 12. Current CLI Limitations

The current CLI does not implement the following commands or options:

- `rri init`
- A separate configuration-management command.
- A standalone module-selection option.
- A command for scanning multiple targets in one invocation.
- A command for automatically probing discovered API endpoints.

Do not assume these capabilities are available unless they are implemented and documented in a future release.

---

For installation instructions, see [Installation Guide](INSTALLATION.md).

For security boundaries and authorization behavior, see [Scope and Safety](SCOPE-AND-SAFETY.md).
