# Build support

Run make from the module root; its Makefile includes [Makefile](Makefile).
The interoperability targets require Bash as well as a POSIX shell.
[.golangci.yml](.golangci.yml) configures lint/formatting and
[interop.Dockerfile](interop.Dockerfile) supplies optional native test engines.
The Docker build context is the module root. `make interop-docker` first prepares
the checksum-pinned downloads listed in [interop-inputs.txt](interop-inputs.txt)
and passes their cache as the `interop-downloads` named build context. Override
`INTEROP_INPUT_CACHE` to reuse another cache directory. Tests run offline.

[interop.sh](interop.sh) runs both external suites. In the CI image,
`XMLSEC_REQUIRE_INTEROP=1` rejects skipped, failed or incomplete test streams.
The full recipe starts the official DSS service and the test-owned Shibboleth
IdP/Jetty, OpenAM/Tomcat and Google GSA deployments; no external service
credentials are required.

See [testing](../docs/testing.md) for commands and prerequisites.

The `authority-http` selection covers AuthnQuery, AssertionIDRequest and NameID
Mapping using OpenAM 16.1.4, plus AuthzDecisionQuery using Google GSA adaptor
4.1.4. The OpenAM test WAR has one disclosed serializer correction in
[openam-nameid-order.patch](openam-nameid-order.patch), compiled offline by
[patch-openam.sh](patch-openam.sh); GSA uses its unmodified upstream example and
handler. See [the coverage boundaries](../docs/saml-authority.md#tests-and-independent-evidence)
for peer defects, the legacy Mapping cipher and GSA's TLS-only response profile.
