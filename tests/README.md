# Repository tests

Cross-package tests are in `integration`; optional native comparisons in `interop`.
`testdata/consumer` is a separate module for public-API checks, run by the root
suite. Unit tests, examples, fuzz targets and benchmarks live beside their packages.

See [testing](../docs/testing.md) for commands, fixtures and Docker prerequisites.
`cmd/dev` provides documentation, example and fuzz runners, pinned W3C suite
diagnostics, language-proof capture/cache commands and the interoperability-log gate.
