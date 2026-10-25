package xdm

// JSONNumber preserves the lexical representation during json-to-xml conversion.
// It is a transient item; parse-json produces ordinary atomic double values.
type JSONNumber struct {
	// Lexical contains the original JSON number token used during json-to-xml conversion.
	Lexical string
}

func (JSONNumber) itemTag() {}
