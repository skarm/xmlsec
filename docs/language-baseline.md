# Language suite baseline

Recorded on 2026-10-25 with Go 1.27.3, darwin/arm64 and `GOMAXPROCS=2`.
Source/module/pin SHA-256:
`bd9dacd6dd358be81a5b2d5711d89e8cf4c71f5684a5539839701ad24c7a4693`.
Reports identify revision `9c30954`, `library_modified=true`; documentation is
outside this checksum. This is the current snapshot; history belongs in Git.
The selected profiles retain restricted claims, with clause evidence tracked
separately from implementation in [the register](conformance.md).

## Full catalogs

All runs traverse unmodified pinned catalogs without filters or case limits.
Main runs select XSD 1.0 datatype/regex rules, assertions enabled, public default
budgets and a one-second case deadline. Every run below has **zero skips**.
Counts are passed / failed / not-applicable:

- XPath 2.0: **15,219 / 9 / 16,593** (31,821).
- XPath 3.0: **19,278 / 20 / 12,523** (31,821).
- XPath 3.1: **22,034 / 16 / 9,771** (31,821).
- XSLT 2.0: **5,672 / 60 / 8,869** (14,601).
- XSLT 3.0: **8,001 / 86 / 6,514** (14,601).

Controls retain the same deadline and catalogs:

- XSD 1.1, XPath 3.1: **22,078 / 16 / 9,727**.
- XSD 1.1, XSLT 3.0: **8,006 / 85 / 6,510**.
- Assertions disabled, XSLT 3.0: **7,990 / 86 / 6,525**.
- Expanded `-limits=language`, XPath 3.1: **22,037 / 13 / 9,771**.
- Expanded `-limits=language`, XSLT 3.0: **8,003 / 84 / 6,514**.
- `-xpath10-compatibility`, XPath 2.0: **0 / 0 / 31,821**.
- The same flag, XPath 3.0 and 3.1: **5 / 0 / 31,816**, each.

QT3 compatibility applies only to explicit catalog dependencies; ordinary cases
remain strict. The 2.0 compatibility control has no applicable cases and exits
unsuccessfully; the 3.0/3.1 controls succeed. Runs with visible failures exit
unsuccessfully. XSD selection does not enable schema validation. Expanded budgets
retain timeout/work/size controls; no uncaught panic occurred.

## Failure backlog

Main-run categories are assertion / harness / resource-limit, not defect counts:

- XPath 2.0: **0 / 0 / 9**.
- XPath 3.0: **13 / 0 / 7**.
- XPath 3.1: **4 / 1 / 11**.
- XSLT 2.0: **49 / 0 / 11**.
- XSLT 3.0: **64 / 5 / 17**.

The case audit covers all **34 distinct QT3** and **119 distinct XSLT** residual
failures across these profiles and controls. Each has a resource, fixture/input,
optional-feature or permitted-outcome disposition; none is silently skipped.
No unclassified concrete mandatory defect remains in this reviewed failure set.
Source review also covers the selected clause/function inventory; incomplete
local and independent evidence retains its own states in the register.

Edition differences explain several visible assertions:

- Ten XPath 3.0 date/fraction fixtures were updated in 2016 for F&O 3.1 bugs
  29749/29788 while retaining `XP30+` dependencies. The selected 2014 REC requires
  half-even rounding; 3.1 truncates. Native 3.1 matches all ten expectations;
  native 3.0 matches the older independent Saxon 9.4 algorithm. The old overflow
  rule in `millisecs-022` is ambiguous; its historical result is an explicit
  interpretation rather than a uniquely prescribed answer.
- SER31 `serialize-xml-007b/015b/016b/020b` retain whole-document validation
  expectations, while the published 3.1 extraction validates selected children.
  SER30 `007c/026b` assume extension schema declarations absent from this host;
  `025b` also contains simultaneous schema and duplicate errors. Ready xmllint
  checks the pinned schemas and extraction rules independently.
- Eight selected-2.0 XSLT fixtures use 3.0-only names/output features or accept
  only one of several static errors. They remain failures. `number-0111` differs
  from the published `xs:integer(round(number($V)))` conversion for a huge value.

Other retained boundaries include DTD whitespace metadata/source construction,
missing publisher resources, optional EXSLT and directory-query collections,
older-edition error codes and simultaneous errors. HTML URI/namespace fixtures
include the disagreement tracked by [qtspecs issue 21](https://github.com/w3c/qtspecs/issues/21).
Literal `>` in XML attributes is permitted; its escaped-only fixtures stay visible.
The five warning harness cases require an optional channel (§6.6.1).
`unparsed-text-2003` needs offline-unavailable HTTP bytes.

`fn-transform-43` parses a valid empty serialized entity as a complete document;
quantified evaluation may encounter that error before a successful witness.
`fn-transform-27` expects different compilation times despite the runner's fixed
clock; `cache=false` is an efficiency hint. `cbcl-matches-004` uses a valid giant
quantifier beyond the regex bound, retaining a resource failure rather than
invalid-syntax success. Schema awareness, W3C streamability and general XML
processor conformance remain separate roles.

## Reproduction and local evidence

Pins: QT3 `201a6e466940cdfc727f4babfedcde5332b9f578`; xslt30-test
`fddf1cf920087e791f13315d68dfbe874d97dc56`. See the
[adapter contract](language-suites.md) and [license/pin file](../build/w3c-suites.json).
Publisher files and generated JSON reports stay outside this repository.

```sh
go build -o /tmp/xmlsec-suites ./tests/cmd/dev
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=qt3 -dir=/absolute/path/to/qt3tests \
  -version=3.1 -xsd-version=1.0 -limits=default -timeout=1s -assertions -report=/tmp/qt31.json
GOMAXPROCS=2 /tmp/xmlsec-suites suites -suite=xslt30 -dir=/absolute/path/to/xslt30-test \
  -version=3.0 -xsd-version=1.0 -limits=default -timeout=1s -assertions -report=/tmp/xslt30.json
```

Repeat for XPath 2.0/3.0 and XSLT 2.0. Controls change `-xsd-version`, omit
`-assertions`, select `-limits=language`, or add `-xpath10-compatibility`.
Clock: `2026-01-01T00:00:00Z`, UTC; Unicode 17.0. Reports record actual versions,
budgets, source/executable hashes, checkout state and decoding policy.

New regressions extend existing test files. `make check`, root race (including
the external consumer), zero-issue lint and all 83 Docker independent-engine
groups pass. [Testing](testing.md) documents ready Saxon 9.4/12.10,
libxml2/libxslt and published-schema controls. Explicit oracle diagnostics remain
separate from exact agreement and do not establish complete clause evidence.
