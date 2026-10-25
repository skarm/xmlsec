// Package transform compiles and runs XPath 1.0/2.0/3.0/3.1, XSLT 1.0 and
// selected Basic XSLT 2.0/3.0 features with one Go engine and a shared immutable
// data model. Full Basic-profile conformance has not been established.
//
// # Compile once, invoke independently
//
// Construct an [Engine] with [NewEngine]. Use [Engine.Parse] for XML input or [Engine.Import]
// to share an existing github.com/skarm/xmlsec/document snapshot without reparsing.
// [Engine.CompileXPath] snapshots namespaces, language version and static base URI;
// [XPath.Evaluate] supplies invocation-local variables and context. [Engine.CompileXSLT]
// binds stylesheet version and static parameters; [Stylesheet.Transform] supplies
// global parameters and an optional initial template or mode.
//
// Documents and compiled programs support concurrent reuse. [Bindings] maps expanded
// [Name] names to immutable [Sequence] values. Values include atomic types,
// read-only nodes, maps, arrays and function items. The zero Sequence is empty;
// a zero [Value] is absent. Array Member and Sequence.At use zero-based Go indices.
//
// # Results, resources and limits
//
// XPath returns a sequence; [Sequence.Text] requires one atomic or node item.
// XSLT [Stylesheet.Execute] returns a typed immutable [Result]; [Result.Serialize]
// returns owned primary bytes, secondary documents and messages in [Output].
// Secondary results do not write files. [Result.WriterTo] binds a context to an
// io.WriterTo serializer. Its WriteTo method, [Result.WriteSecondary] and
// [Stylesheet.Write] return byte counts and allow partial output on error.
// Ordinary execution retains the complete result; serialization writes common
// formats incrementally and uses intermediate storage for specialized options.
// [Engine.ParseReader] and [Engine.CompileXSLTReader] parse incrementally. For
// independent records, [Stylesheet.WriteRecords] retains one record and its
// result alongside parser state, stylesheet, parameters and invocation resources;
// it does not retain the complete enclosing document or collect all output.
//
// [Config] supplies bounded defaults and an optional application-approved [Resolver].
// There is no implicit file/network lookup or process-environment access. Resolver
// readers are closed; callbacks and blocking I/O must honor cancellation.
// [Limits] bounds program/input/output bytes, operations, nodes and recursion.
// A zero Timeout selects the default timeout; it does not disable it. These are
// cooperative in-process controls, not OS memory or CPU isolation.
//
// # XMLDSig integration and scope
//
// Engine implements the reference extension interface for explicitly approved
// XPath 1.0, Filter2 and restricted XSLT 1.0 programs. Configure AllowedPrograms
// and the reference processor's transform allowlist; XMLDSig algorithm URIs retain
// their own language semantics, regardless of standalone program versions.
//
// [Error] preserves operation, standard XPath/XSLT codes where available, and error
// causes. Application functions, packages and collections use explicit adapters.
// Schema awareness and W3C streamable XSLT execution are unsupported; independent
// record streaming is available through [Stylesheet.WriteRecords].
// The supported profiles do not establish full W3C conformance.
// Unicode normalization uses Unicode 17 tables without inserting Stream-Safe
// joiners. Exact normalization retains an unfinished combining sequence until
// its boundary; see docs/streaming.md for memory requirements.
package transform
