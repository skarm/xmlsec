// Command xmlsec exposes the library's XML signatures, encryption, keys,
// XPath/XSLT, offline PKI/evidence and SAML operations through bounded local I/O.
//
// # Commands and I/O
//
// Run xmlsec --help for command groups, xmlsec help signature for a group, or
// xmlsec signature sign -h for operation flags. Flags follow the complete command
// name. Build with go build -o bin/xmlsec ./cmd/xmlsec from the module root.
//
// Input/output streams use - where supported. Keys, password files, configuration
// and resource allowlists use regular files. XML and binary results go to the
// selected output; verification and inspection reports are JSON. Root/group help
// uses stdout, while operation flag help and diagnostics use stderr.
//
// # Trust and publication
//
// Operator configuration supplies exact keys, trust anchors, resource URIs and
// transform programs. Embedded descriptions never expand trust or enable implicit
// network access. Verification diagnostics are not partially authenticated payloads;
// inspection reports are unverified. Local file output uses temporary-file/rename
// publication, with separate publication for multiple output files.
//
// The CLI calls the same public APIs as library users. Offline SAML checks do not
// consume shared replay state or create browser sessions. See docs/cli.md in the
// repository for command recipes, configuration formats and exit codes.
package main
