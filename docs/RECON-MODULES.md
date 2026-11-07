# Reconnaissance Modules

This document describes the reconnaissance and analysis modules currently implemented in RRI (Recon Intelligence).

RRI currently includes ten main modules:

1. Technology Fingerprinting.
2. API Discovery.
3. HTTP Headers Analysis.
4. Passive Security Checks.
5. Website Crawler.
6. Path Discovery.
7. JavaScript Analysis.
8. DNS Information.
9. HTTP Information.
10. TLS Certificate Analysis.

Each module analyzes collected response data and produces structured results for the CLI, correlation engine, and reporting engine.

## 1. Module Architecture

The modules are located in the `modules/` directory.

Each module has a specific responsibility and uses the shared HTTP engine when it needs to retrieve data.

The initial target response is fetched by the scan orchestrator and passed to the modules. API Discovery may additionally retrieve a limited number of authorized JavaScript assets.

The modules are designed to identify indicators and collect evidence. Their findings should not automatically be interpreted as confirmed vulnerabilities.

## 2. Technology Fingerprinting

Source file: `modules/technology.py`

### 2.1 Purpose

Technology Fingerprinting identifies technologies that may be used by the target website.

It examines available HTTP response headers, cookies, HTML metadata, markup, and inline JavaScript.

The module uses signatures and indicators rather than a complete browser engine or runtime framework analysis.

### 2.2 Evidence Sources

The detector currently examines the following sources.

#### HTTP Response Headers

It checks selected headers, including:

- `Server`
- `X-Powered-By`
- `CF-Ray`
- `Via`

Examples of possible indicators include:

- nginx
- Apache
- LiteSpeed
- Microsoft IIS
- Caddy
- Cloudflare
- PHP
- Express
- ASP.NET
- Next.js
- Nuxt
- Amazon CloudFront

A header value is an indicator, not definitive proof of the underlying infrastructure.

#### Cookies

The module checks for selected cookie-name patterns associated with common platforms and frameworks.

Examples include:

- `PHPSESSID`
- `laravel_session`
- `wordpress_logged_in_`
- `wp-settings-`
- `csrftoken`
- `sessionid`
- `connect.sid`
- `ASP.NET_SessionId`
- `JSESSIONID`

Cookie names can be changed, customized, or reused. Their presence alone does not prove that a particular framework is running.

#### HTML Metadata

The detector examines generator metadata and other HTML indicators.

Examples include:

- WordPress
- Drupal
- Joomla
- Wix
- Shopify
- Next.js

#### HTML and Asset References

The module checks selected HTML paths, script references, stylesheet references, and inline JavaScript indicators.

It includes patterns associated with technologies such as:

- React
- Vue
- Angular
- AngularJS
- jQuery
- Next.js
- Nuxt
- WordPress
- Drupal
- Joomla
- Shopify

### 2.3 Scoring and Confidence

Technology evidence is accumulated into a score for each detected technology.

The current confidence thresholds are:

| Score | Confidence |
|---|---|
| 80 or higher | High |
| 45–79 | Medium |
| Below 45 | Low |

Scores are capped at 100.

Multiple indicators may contribute to the same technology result. Evidence is collected and duplicate evidence is avoided.

### 2.4 Result Structure

Technology results include fields such as:

- `name`
- `category`
- `score`
- `evidence`
- `confidence`
- `evidence_count`

The module also returns scan information such as target, HTTP status, result count, and status.

### 2.5 Limitations

Technology Fingerprinting has the following limitations:

- Detection is based on signatures and heuristic indicators.
- It does not guarantee that an identified technology is currently active.
- It does not reliably identify exact software versions.
- Header values can be hidden, modified, or misleading.
- Cookie names can be customized.
- HTML and JavaScript indicators may be incomplete or ambiguous.
- External JavaScript and CSS content is not downloaded by this module.

A detected technology should be treated as an observation requiring verification.

## 3. API Discovery

Source file: `modules/api_discovery.py`

### 3.1 Purpose

API Discovery searches available page content and authorized JavaScript assets for references to potential API endpoints and API documentation.

It is a discovery module, not an API vulnerability scanner.

### 3.2 Evidence Sources

The module examines:

- HTML content.
- Inline JavaScript.
- External JavaScript assets that are within the authorized scope.

It extracts endpoint-like references from these sources.

### 3.3 Endpoint Patterns

The current implementation recognizes patterns associated with paths such as:

- `/api`
- `/api/v1/...`
- `/rest/...`
- `/graphql/...`
- `/gql/...`
- `/v1/...`

These patterns are indicators of possible API routes.

The module also recognizes references that may indicate OpenAPI or Swagger documentation.

Recognizing such a reference does not mean the specification was retrieved or parsed.

### 3.4 GraphQL Indicators

The module checks for GraphQL-related indicators, including:

- `graphql`
- `GraphQLClient`
- `ApolloClient`
- `urql`

When relevant indicators are found, it may add common GraphQL candidate paths, including:

- `/graphql`
- `/api/graphql`
- `/gql`

These are heuristic candidates. Their existence and accessibility are not confirmed.

### 3.5 Endpoint Classification

Discovered entries are classified into categories such as:

- REST
- GraphQL
- API Documentation

The module assigns heuristic scores to discovered entries and combines evidence when the same URL is identified more than once.

A score represents the module's discovery heuristic, not endpoint validity or vulnerability severity.

### 3.6 JavaScript Asset Handling

The module may fetch external JavaScript assets to inspect their contents.

The current implementation applies these limits:

| Limit | Value |
|---|---:|
| Maximum script files | 10 |
| Maximum script URL length | 2,048 characters |
| Maximum discovered endpoints | 300 |
| Maximum source evidence length | 500 characters |

The configured script-file limit can be adjusted when creating the module, within the supported range of 0 to 50.

Before fetching an asset, the module:

1. Resolves its reference relative to the page URL.
2. Validates the resulting URL.
3. Checks that it belongs to the authorized scope.
4. Applies the script-count limit.
5. Fetches it through the shared HTTP engine.
6. Checks the final response URL against the scope.
7. Analyzes the returned content.

Only authorized JavaScript assets are fetched.

### 3.7 Important Security Boundary

API Discovery does not send requests to discovered API endpoints.

For example, discovering a reference to `/api/v1/users` does not cause RRI to request that endpoint automatically.

This keeps endpoint discovery separate from active API probing.

### 3.8 Result Information

The module returns information including:

- Scan status.
- Target.
- Discovered endpoints.
- Endpoint count.
- Script discovery count.
- Script fetch count.
- Skipped script count.
- Error information when applicable.

Individual endpoint entries include their URL, category, score, sources, and evidence.

### 3.9 Limitations

API Discovery has several limitations:

- It uses pattern matching rather than JavaScript abstract syntax tree analysis.
- It does not execute JavaScript.
- It does not inspect all possible runtime-generated routes.
- OpenAPI and Swagger references are indicators; specifications are not fully parsed.
- GraphQL candidate paths are heuristic.
- Endpoint references may be obsolete, inaccessible, or unrelated to the active application.
- It does not verify endpoint functionality.
- It does not test authentication, authorization, input validation, or API vulnerabilities.

Discovered endpoints must be manually verified before being treated as active application routes.

## 4. HTTP Headers Analysis

Source file: `modules/headers_analysis.py`

### 4.1 Purpose

HTTP Headers Analysis examines response headers and cookie attributes for selected security-related configuration indicators.

It focuses on the presence and selected properties of common browser security headers.

### 4.2 Security Headers

The current implementation checks the following headers:

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Controls browser HTTPS enforcement through HSTS. |
| `Content-Security-Policy` | Defines browser resource-loading restrictions. |
| `X-Frame-Options` | Provides legacy framing restrictions. |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing. |
| `Referrer-Policy` | Controls referrer information sent by browsers. |
| `Permissions-Policy` | Controls selected browser features. |
| `Cross-Origin-Opener-Policy` | Controls browsing-context relationships. |
| `Cross-Origin-Resource-Policy` | Controls cross-origin resource loading. |
| `Cross-Origin-Embedder-Policy` | Controls cross-origin embedding requirements. |

### 4.3 HSTS Checks

HSTS analysis is performed only for HTTPS responses.

The module checks:

- Whether the header is present.
- Whether a valid `max-age` value is present.
- Whether `max-age` is zero.
- Whether the configured duration is shorter than six months.

A short or missing duration may produce a finding depending on the observed configuration.

### 4.4 Content Security Policy Checks

The module performs selected heuristic checks for:

- Missing CSP.
- `unsafe-inline`.
- `unsafe-eval`.
- Wildcard values in selected directives.
- Missing `frame-ancestors`.

These checks do not constitute a complete CSP parser or policy assessment.

A policy can have other weaknesses that are not detected by the current implementation.

### 4.5 Other Security Header Checks

The module checks the presence of selected standard security headers.

For example, it checks for missing:

- `X-Frame-Options`, unless an applicable CSP `frame-ancestors` directive is present.
- `X-Content-Type-Options`.
- `Referrer-Policy`.
- `Permissions-Policy`.

It also reports the absence of selected cross-origin isolation headers as informational observations.

The absence of these isolation headers is not automatically a vulnerability.

### 4.6 Information Disclosure Indicators

The module checks whether response headers expose values through:

- `Server`
- `X-Powered-By`

Their presence may produce a low-severity information disclosure observation.

Header disclosure alone does not prove that the exposed software is vulnerable.

### 4.7 Cookie Security Checks

The module examines `Set-Cookie` headers and selected cookie attributes:

- `Secure`
- `HttpOnly`
- `SameSite`

It identifies missing or invalid attributes and checks for `SameSite=None` without `Secure`.

Cookie findings depend on the cookie configuration visible in the response.

The module does not establish the full security requirements of every application cookie or session workflow.

### 4.8 Severity Categories

Findings use the following severity categories:

- Critical
- High
- Medium
- Low
- Info

The current header analysis rules primarily produce medium, low, and informational findings.

Severity is a heuristic classification of the observed configuration, not a confirmed impact assessment.

### 4.9 Result Structure

The module returns:

- Status.
- Target.
- HTTP status.
- Findings.
- Finding count.
- Severity counts.
- Error information when applicable.

Each finding includes fields such as:

- `id`
- `title`
- `category`
- `severity`
- `evidence`
- `description`
- `recommendation`

### 4.10 Limitations

- Header presence does not prove that the complete application is secure.
- CSP analysis is heuristic rather than standards-complete.
- HSTS analysis focuses on selected `max-age` properties.
- Cross-origin isolation checks are presence-oriented.
- Cookie parsing has limitations.
- Reverse proxies and application infrastructure may alter response headers.
- The module does not test browser behavior or application logic.

## 5. Passive Security Checks

Source file: `modules/security_checks.py`

### 5.1 Purpose

Passive Security Checks analyze the retrieved response for potentially sensitive information and security-relevant indicators.

The module does not exploit vulnerabilities or automatically visit discovered paths.

### 5.2 Analyzed Indicators

The current implementation searches for several categories of indicators.

#### Administrative Path References

Examples include references containing:

- `admin`
- `administrator`
- `wp-admin`
- `dashboard`
- `manage`

A reference to an administrative path does not establish that the path exists or is accessible.

#### Sensitive File References

The module looks for references to potentially sensitive files, including patterns associated with:

- `.env`
- Backup files.
- Old or original files.
- Editor temporary files.
- SQL dumps.
- ZIP, TAR, GZ, and 7z archives.

A reference does not prove that the file is publicly accessible.

#### Source Map References

The module checks for `sourceMappingURL` indicators.

A source map reference does not establish that the referenced source map can be retrieved.

#### Debug and Error Information

The module searches for indicators associated with debug pages and error details.

Examples include:

- Laravel Ignition.
- Whoops.
- Werkzeug.
- Django.
- Symfony.
- ASP.NET error information.
- Python tracebacks.
- Java exceptions.
- SQL errors.
- Database exceptions.
- PHP fatal errors.

These patterns may appear in examples, documentation, or harmless application content.

They require contextual verification.

#### Configuration-Related Indicators

The module recognizes selected configuration-related key patterns, including:

- AWS-related secret or access-key indicators.
- `DB_PASSWORD`
- `DATABASE_URL`
- `SECRET_KEY`
- `APP_KEY`
- `PRIVATE_KEY`
- `API_SECRET`

The module is designed to report the indicator without reproducing the associated secret value in the report.

A matching key name does not prove that a valid credential has been exposed.

#### Directory Listing Indicators

The module checks for text patterns such as:

- `Index of /`

This is an indicator of a possible directory listing page, not proof of a security issue.

#### Internal Paths and Addresses

The module searches for indicators of internal filesystem paths and private IPv4 addresses.

Their presence may be intentional or harmless, depending on context.

### 5.3 Processing Limits

The current implementation applies the following limits:

| Limit | Value |
|---|---:|
| Maximum response body analyzed | 2 MiB |
| Maximum findings | 100 |
| Maximum evidence length | 300 characters |
| Maximum page-analysis input | 2 MiB |

These limits help bound processing and report size.

### 5.4 Severity and Confidence

Findings are assigned heuristic severity and confidence values based on their patterns and available evidence.

They should be interpreted as indicators requiring manual review.

A higher confidence value does not independently prove exploitability.

### 5.5 Result Structure

The module returns structured information including:

- Scan status.
- Target.
- Findings.
- Finding count.
- Severity information.
- Error information when applicable.

Findings include descriptive information and evidence intended to support manual verification.

### 5.6 Important Limitations

Passive Security Checks does not:

- Request discovered administrative paths.
- Retrieve referenced backup files.
- Download referenced source maps.
- Attempt authentication bypass.
- Exploit debug pages.
- Test discovered credentials.
- Send payloads to application endpoints.
- Confirm that a referenced file is accessible.
- Establish that a configuration indicator contains a valid secret.

The module analyzes available response content only.

## 6. Website Crawler

Source file: `modules/crawler.py`

### 6.1 Purpose

The crawler collects internal links from HTML pages within the authorized scope. It follows same-origin links only and respects all scope and safety controls.

### 6.2 Limits

| Limit | Default |
|---|---:|
| Maximum crawl depth | 3 |
| Maximum pages fetched | 20 |

### 6.3 Behavior

- Follows only same-origin links (no subdomains or external domains).
- Skips static asset URLs (images, CSS, fonts, archives, etc.).
- Deduplicates URLs and paths.
- Records verification status: `discovered`, `tested`, `confirmed`, `failed`.
- Every fetch is scope-checked before and after the request.

### 6.4 Result Structure

Returns `discovered_urls` and `discovered_paths` lists, plus `pages_fetched`, `pages_failed`, and unique counts.

## 7. Path Discovery

Source file: `modules/path_discovery.py`

### 7.1 Purpose

Discovers paths on the target domain from multiple passive sources: HTML attributes, inline JavaScript, external JavaScript files, and crawl results.

### 7.2 Sources

- HTML `href`, `src`, `action`, `data-url`, `data-src` attributes.
- Inline JavaScript string literals containing path-like values.
- External JavaScript files (fetched via the shared HTTP engine, scope-checked).
- Crawl results from the Website Crawler module.

### 7.3 Wordlist Testing

Optional wordlist-based path testing is disabled by default. When enabled with a wordlist, it sends GET requests to test path existence and records the result. This is the only module that performs active path probing, and only when explicitly requested.

### 7.4 Result Structure

Returns `discovered_paths`, `tested_paths`, `confirmed_paths`, `failed_paths`, plus path count and script analysis metadata.

## 8. JavaScript Analysis

Source file: `modules/js_analysis.py`

### 8.1 Purpose

Performs deep passive analysis of JavaScript files to extract recon-relevant patterns: API paths, internal SPA routes, full URLs, source map references, and configuration references.

### 8.2 Extraction Patterns

- **API paths**: `/api/...`, `/rest/...`, `/graphql/...`, `/gql/...`, `/v1/...`
- **Internal routes**: `path: "/..."`, `route: "/..."`, `to: "/..."` patterns
- **URLs**: Full `http://` and `https://` URLs in string literals
- **Source map references**: `//# sourceMappingURL=...`
- **Configuration references**: Keys matching `api_key`, `secret`, `token`, `password`, `auth` patterns

### 8.3 Limits

| Limit | Default |
|---|---:|
| Maximum script files | 10 |
| Maximum script size | 512 KB |

### 8.4 Result Structure

Returns `analyzed_scripts` (per-file results), plus aggregated lists: `all_api_paths`, `all_routes`, `all_urls`, `all_source_map_refs`, `all_config_refs`.

## 9. DNS Information

Source file: `modules/dns_info.py`

### 9.1 Purpose

Passively collects DNS records (A, AAAA) for the target domain using the system resolver. This is information gathering only — records are not used to authorise or route requests.

### 9.2 Result Structure

Returns `records` list with `record_type`, `hostname`, `values`, and `discovery_source` fields.

## 10. HTTP Information

Source file: `modules/http_info.py`

### 10.1 Purpose

Extracts structured HTTP response information from the initial page fetch: status code, headers, content type, content length, server header, redirect count, and final URL.

### 10.2 Result Structure

Returns `http_info` dict with all response metadata, plus summary fields: `server`, `content_type`, `content_length`, `http_status`, `header_count`.

## 11. TLS Certificate Analysis

Source file: `modules/tls_analysis.py`

### 11.1 Purpose

Inspects the TLS/SSL connection and certificate for the target hostname. Establishes a TLS connection to port 443 only and extracts certificate details passively.

### 11.2 Extracted Information

- TLS version negotiated
- Cipher suite
- Certificate validity (dates, issuer, subject)
- Hostname verification result

### 11.3 Scope Enforcement

The hostname must be in the authorized scope before a TLS connection is attempted. No HTTP requests are sent — only a TLS handshake.

### 11.4 Result Structure

Returns `tls_info` dict with `tls_version`, `cipher_suite`, `cert_valid`, `cert_hostname_valid`, `cert_issuer`, `cert_subject`, `cert_not_before`, `cert_not_after`, and `error` fields.

## 12. Shared Module Behavior

Although each module has a separate responsibility, they share several design characteristics.

### 6.1 Structured Results

Modules return structured Python data rather than writing their own independent reports.

This allows the CLI to summarize their results and the correlation engine to analyze relationships between them.

### 6.2 Bounded Processing

The implementation applies limits to selected inputs and outputs, including:

- HTTP response size.
- Number of JavaScript assets.
- Number of discovered API endpoints.
- Number of security findings.
- Evidence length.

These limits reduce unbounded processing and oversized results.

### 6.3 Shared HTTP Engine

Modules that need additional HTTP requests use the shared HTTP engine.

This preserves common scope, DNS, redirect, timeout, and response-size controls.

### 6.4 Evidence-Based Findings

The modules report observations based on collected evidence.

A finding is not automatically a confirmed vulnerability, and a discovery result is not automatically an accessible or active resource.

## 13. Correlation Between Modules

After module execution, the correlation engine can identify relationships between selected findings.

Current relationships include:

- API endpoint and security finding overlap.
- API endpoint and header finding overlap.
- API endpoint and technology evidence overlap.

Correlation is limited to evidence associated with the same normalized origin.

It does not independently verify the underlying observation or establish exploitability.

See [Architecture](ARCHITECTURE.md) for the correlation engine's position in the overall processing flow.

## 14. Interpreting Results

When reviewing RRI output:

1. Read the finding title and category.
2. Examine the supplied evidence.
3. Identify the source module.
4. Consider whether the evidence could have a harmless explanation.
5. Verify the observation manually using authorized methods.
6. Assess impact separately before classifying it as a vulnerability.

Do not report a security vulnerability solely because a heuristic indicator appeared in an RRI report.

## 15. Module Extension Guidelines

New reconnaissance modules should follow these principles:

- Have a clearly defined responsibility.
- Reuse the shared HTTP engine when network access is required.
- Respect the authorized scope.
- Apply bounded input and output processing.
- Avoid automatic active probing unless explicitly designed, authorized, and separately controlled.
- Return structured results.
- Preserve evidence needed for manual verification.
- Include automated tests for normal behavior, invalid input, and security boundaries.
- Document detection logic and known limitations.

New modules should not bypass the shared network safety controls.

---

For the overall system design, see [Architecture](ARCHITECTURE.md).

For scope enforcement and network safety, see [Scope and Safety](SCOPE-AND-SAFETY.md).

For report formats and output behavior, see [Reporting](REPORTING.md).
