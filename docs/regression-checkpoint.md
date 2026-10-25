# Regression checkpoint: 22 October 2026

The R1–R6 fixes are in commit `9e1af15`. The working tree was clean at the start
of this follow-up. Verification used Go 1.27.3 on macOS/arm64. The normative
register infrastructure was subsequently committed as `3ac496a`; its clause
inventory remains partial.

Two separate review passes checked the corrected behavior:

1. Resource and arithmetic paths: binary integer/rational accounting, growth
   preflight, AST/VM and higher-order evaluation, casts, bindings/containers,
   approved-program compilation, XSLT calls, cancellation and int64 promotion.
2. XML and validation paths: source namespace context and immutable snapshots,
   stylesheet/QName import, detached parameter round trips and preflight before
   resolver/signer calls, nil/zero KeyInfo and subsequence cardinality across
   language versions and backwards-compatible processing.

Neither pass identified an additional confirmed production defect in the R1–R6
scope. These are maintainer review passes and regression checks, not an
independent security audit or a full standards-conformance assessment.

The following gates passed:

```sh
make check
make lint
go test -race -count=1 -timeout=5m ./...
go test -count=1 -v ./transform ./transform/internal/xpath ./xmldsig \
  -run 'Test(Numeric|ApprovedProgramNumeric|Integer(Multiplication|Minimum)|Subsequence|XSLTLiteralNamespace|Template(ObjectNamespace|StylesheetNamespace|KeyInfoRoot)|ImportedStylesheet|Detached(Program|DamagedProgram|VerifierPreflights))'
```

The last command names the existing component tests containing the small
reproductions and boundary/negative cases. No new test-only files were needed.
The raw-certificate RetrievalMethod profile already supports a single optional
Base64 transform; [compatibility](compatibility.md) and [usage](usage.md) state
that explicitly.

This checkpoint does not close later roadmap extensions. Full normative
inventory, external suites, additional cryptographic/protocol profiles and
historical AdES validation retain the gaps in the
[conformance register](conformance.json).
