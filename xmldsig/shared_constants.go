package xmldsig

const (
	// Identifies the reference-coverage check in detailed verification diagnostics.
	stageCoverage = "coverage"
	// Identifies reference digest verification in detailed diagnostics.
	stageDigest = "digest"
	// Identifies transform-policy checks performed before reference resource I/O.
	stagePreflight = "preflight"
	// Identifies reference transform execution in detailed verification diagnostics.
	stageProcess = "process"
	// Identifies XML structure checks that precede cryptographic verification.
	stageStructure = "structure"
	// Names a ds:Manifest; recursive checking follows the caller's ManifestPolicy.
	nameManifest = "Manifest"
)

const (
	// Diagnostic stage label for explicitly authorized resource resolution.
	nameResolve = "resolve"
	// Diagnostic stage label for reference transform processing.
	nameTransform = "transform"
)
