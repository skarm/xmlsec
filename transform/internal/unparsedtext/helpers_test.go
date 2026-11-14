package unparsedtext_test

const textResourceURI = "urn:example:text"

type mediaReader struct {
	*trackedReader
	media string
}

func (r mediaReader) MediaType() string { return r.media }
