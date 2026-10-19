# Repository tests

Cross-package tests are in `integration`; optional native comparisons in `interop`.
`testdata/consumer` is a separate module for public-API checks, run by the root
suite. Unit tests, examples, fuzz targets and benchmarks live beside their packages.

See [testing](../docs/testing.md) for commands, fixtures and Docker prerequisites.
`cmd/dev` provides the documentation, example and fuzz runners.
