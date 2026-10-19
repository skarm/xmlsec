package tree

// NormalizeLexicalForTest exposes the lexical phase to ownership tests.
func NormalizeLexicalForTest(data []byte) ([]byte, error) { return normalizeLexical(data) }

// RemoveDotSegmentsForTest exposes RFC 3986 path normalization to its conformance tests.
func RemoveDotSegmentsForTest(path string) string { return removeDotSegments(path) }

// JoinURIReferencesForTest exposes RFC 3986 resolution to its conformance tests.
func JoinURIReferencesForTest(base, reference string) (string, error) {
	return joinURIReferences(base, reference)
}
