# Scope and Safety

This document describes how RRI (Recon Intelligence) defines authorized targets, validates network destinations, controls HTTP requests, and limits reconnaissance activity.

RRI is intended to be used only against systems that the operator owns or is explicitly authorized to assess.

## 1. Authorization Is Required

Before running RRI, the operator must have permission to assess the target.

The presence of a publicly accessible website does not grant permission to perform security testing against it.

The operator is responsible for:

- Obtaining appropriate authorization.
- Confirming that the supplied target belongs to the authorized assessment.
- Respecting contractual and program-specific testing restrictions.
- Avoiding disruption to services and users.
- Reviewing findings before taking further action.

RRI does not independently verify legal authorization.

## 2. Runtime Target Selection

The target is supplied explicitly through the CLI:

    rri -u https://example.com

RRI derives its default authorized scope from the supplied target URL.

The normal CLI workflow does not require a fixed target domain in a configuration file.

The target URL is validated before the initial HTTP request is made.

## 3. Default Scope Rules

When the scope is derived from a target URL, the current default behavior is:

- The exact hostname in the target URL is authorized.
- Subdomains are not automatically included.
- All paths on the authorized hostname are allowed by default.
- Other hostnames are outside the default scope.
- Unsupported URL schemes and ports are rejected.

For example, when the target is:

    https://example.com

The default scope includes:

- `https://example.com/`
- `https://example.com/products`
- `https://example.com/api/v1/items`

It does not automatically include:

- `https://admin.example.com`
- `https://api.example.com`
- `https://example.net`

A hostname that appears related to the target is not automatically authorized.

## 4. URL Validation

The scope engine validates URLs before they are accepted.

The current implementation includes checks for:

- HTTP and HTTPS schemes.
- Valid hostnames.
- Hostname normalization using IDNA.
- URL credentials.
- Supported network ports.
- Malformed URL values.
- Whitespace and control characters.
- Backslashes.
- URL fragments.
- Unsafe or ambiguous path forms.
- IP-literal targets.

The current scope implementation accepts HTTP port 80 and HTTPS port 443.

Other ports are rejected.

IP-literal target URLs are rejected by the scope engine.

These restrictions are part of the current implementation and may change only through an explicitly reviewed code change.

## 5. Hostname Matching

Hostname matching is performed against normalized hostnames.

The implementation avoids treating a hostname suffix as proof that another hostname belongs to the authorized target.

For example, authorizing `example.com` does not authorize:

- `notexample.com`
- `example.com.attacker.invalid`
- `admin.example.com`

Subdomains require explicit authorization through supported scope configuration in the core component.

However, the current CLI does not expose an option to load a custom scope configuration file or add additional authorized hostnames.

## 6. Path Validation

The default runtime scope allows all paths on the exact authorized hostname.

The scope component also supports path restrictions when explicit scope configuration is used.

The current implementation rejects selected unsafe or ambiguous path forms, including:

- Encoded path characters containing `%`.
- Backslashes.
- Query strings in scope path definitions.
- Fragments in scope path definitions.
- Repeated leading or internal slash forms.
- Dot and dot-dot path segments.
- Control characters.

Path checks are performed separately from hostname checks.

A URL must satisfy both the hostname and path rules to be authorized.

## 7. DNS and IP Address Safety

File: `core/dns_resolver.py`

RRI uses `SafeDNSResolver` through its HTTP engine.

The resolver:

1. Resolves the requested hostname.
2. Applies a DNS timeout.
3. Validates the returned address records.
4. Checks address family and socket record properties.
5. Rejects addresses that are not globally routable.
6. Removes duplicate validated addresses.

The resolver rejects an entire DNS answer if any returned address is invalid or non-global.

It does not simply discard unsafe records and continue with the remaining records.

This strict behavior reduces the risk of a hostname resolving to a mixture of public and non-public destinations.

### IP Validation

File: `core/network_safety.py`

The network safety component uses Python's IP address handling to determine whether an address is globally routable.

IPv4-mapped IPv6 addresses are normalized to their embedded IPv4 addresses before validation.

Addresses that fail the global-address check are rejected.

The exact classification follows the behavior of the Python IP address library available in the running environment.

## 8. HTTP Request Controls

File: `core/http_engine.py`

The shared HTTP engine applies controls to network communication.

The current defaults include:

| Control | Default |
|---|---:|
| Total request timeout | 15 seconds |
| Maximum response body | 2 MiB |
| Maximum redirects | 5 |
| Maximum response headers | 128 |
| Maximum header field size | 8,190 bytes |
| Maximum header line size | 8,190 bytes |

The implementation validates relevant constructor parameters before using them.

### Connection Behavior

The HTTP engine:

- Uses aiohttp.
- Uses the safe DNS resolver.
- Uses a default SSL context.
- Disables environment proxy inheritance with `trust_env=False`.
- Disables automatic redirect handling.
- Requests identity content encoding.
- Reads response bodies in bounded chunks.

The response-size limit is enforced while reading the response.

Automatic decompression is disabled, so the limit applies to the raw response bytes received by the engine.

## 9. Redirect Protection

File: `core/redirect_guard.py`

RRI does not rely on automatic HTTP redirect following.

Instead, redirects are handled through the redirect guard.

Before following a redirect, the guard validates:

- The current URL.
- The redirect destination.
- The redirect count.
- The resulting URL.
- Whether the destination remains within the authorized scope.

Redirect destinations outside the authorized scope are blocked.

The HTTP engine also rejects ambiguous redirect responses, including responses containing duplicate Location headers.

This prevents a redirect from silently expanding the scan to another hostname.

## 10. JavaScript Asset Restrictions

File: `modules/api_discovery.py`

API Discovery may retrieve external JavaScript assets to identify potential API references.

The module applies the following restrictions:

- Only assets within the authorized scope are eligible.
- The number of scripts is limited.
- Script URL length is limited.
- Each URL is validated before fetching.
- The final response URL is checked after redirects.
- Requests are made through the shared HTTP engine.

The default maximum number of script files is 10.

The module does not fetch arbitrary external scripts merely because they are referenced by a page.

## 11. Discovery Is Not Active Probing

RRI separates discovery from active testing.

### API Discovery

Finding an API endpoint does not cause RRI to send a request to that endpoint.

### Passive Security Checks

Finding a reference to a sensitive path does not cause RRI to visit that path.

### Source Maps

Finding a source map reference does not cause RRI to download the referenced source map.

### Configuration Indicators

Finding a configuration-related key does not cause RRI to test the associated value as a credential.

These boundaries reduce unnecessary requests and keep the current reconnaissance workflow passive.

## 12. Fail-Closed Behavior

RRI is designed to reject operations when authorization or safety validation fails.

Examples include:

- A target outside the authorized scope.
- An invalid URL.
- An unsupported scheme or port.
- An unauthorized redirect.
- A DNS result containing a non-global address.
- An invalid redirect destination.

The HTTP engine checks the requested URL against the scope before creating a network session.

A failed authorization check prevents the request from proceeding through the normal HTTP engine workflow.

## 13. Limitations of the Safety Model

The implemented controls reduce several common network risks, but they do not guarantee complete protection against every possible attack or environment-specific behavior.

Important limitations include:

- DNS and network behavior can vary across operating systems and runtime environments.
- Python IP classification depends on the installed Python version.
- Application-level behavior may not be visible from passive response analysis.
- A safe URL check does not prove that the target operator has granted legal authorization.
- The tool does not provide a general-purpose sandbox for arbitrary future modules.
- Future network-enabled modules must preserve the shared scope and HTTP safety controls.
- Custom scope configuration is available in the core component but is not currently exposed through the CLI.

Operators should review the actual target, authorization boundaries, and assessment rules before every scan.

## 14. Safe Development Requirements

New network-related functionality must:

1. Use the shared HTTP engine where applicable.
2. Validate requested URLs against the authorized scope.
3. Preserve DNS validation.
4. Preserve redirect validation.
5. Apply bounded timeouts and response processing.
6. Avoid automatically probing discovered endpoints unless a separately authorized active-testing feature is explicitly designed.
7. Include tests for unauthorized destinations and malformed input.
8. Fail closed when required authorization checks cannot be completed.

A new module must not bypass the network safety model to perform direct unrestricted requests.

## 15. Responsible Use

RRI is a reconnaissance and analysis tool.

Its results are not proof of vulnerability, and its safety controls are not a substitute for authorization or responsible testing practices.

Use RRI only within the scope of an approved assessment.

---

For command-line behavior, see [CLI Reference](CLI.md).

For implementation details, see [Architecture](ARCHITECTURE.md).

For module-specific discovery behavior, see [Recon Modules](RECON-MODULES.md).
