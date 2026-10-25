# Source provenance

XPath/XSLT language and serialization sources derive from
[lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab](https://github.com/lestrrat-go/helium/tree/7362c0a70122a757780f4d0b545a9b370dead6ab).
Adapted files retain origin, copyright and modification notices; the full notice
is in [MIT-helium.txt](../licenses/MIT-helium.txt). Grammar metadata and the adapted
pattern parser from knroy/go-xml retain [their MIT notice](../licenses/MIT-knroy-go-xml.txt).

The private `transform/internal/{xdm,xpath,xslt,pattern}` packages adapt those
sources to the project's XML storage, immutable public values, language profiles,
context cancellation, resource policy and execution budgets. They are maintained
as part of this module. [transform](transforms.md) describes the public API.
The shared `internal/packageversion` parser retains the same origin and license;
the XSLT compiler and development suite adapter use it for package-version ranges.

Unicode normalization tables come from `golang.org/x/text`. The conformance fixture
retains its Unicode notice; see [Unicode-3.0.txt](../licenses/Unicode-3.0.txt).
