# Security policy

The API is experimental. Full standards conformance and an independent security
audit have not been established. No stable-release support or security response
time is promised. Use a Go toolchain with security fixes that meets the
requirements in [go.mod](go.mod).

Supported profiles and limitations are documented in [compatibility](docs/compatibility.md).
Applications must configure trust, signature coverage and resource access; see the
[API guide](docs/usage.md). Embedded keys and certificates do not establish trust.
Transform execution has in-process limits, without OS isolation. Memory state/replay
stores coordinate one process.

## Reporting vulnerabilities

Use [GitHub private vulnerability reporting](https://github.com/skarm/xmlsec/security/advisories/new)
if enabled. Its availability has not been confirmed. Otherwise, arrange a working
private contact with the maintainer before sharing vulnerability details.

Include the affected revision, impact and a minimal synthetic reproduction.
Keep exploit details and confidential documents out of public issues. Never include
private keys or live tokens in a report.
