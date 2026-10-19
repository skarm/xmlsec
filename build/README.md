# Build support

Run make from the module root; its Makefile includes [Makefile](Makefile).
[.golangci.yml](.golangci.yml) configures lint/formatting and
[interop.Dockerfile](interop.Dockerfile) supplies optional native test engines.
The Docker build context is the module root.

See [testing](../docs/testing.md) for commands and prerequisites.
