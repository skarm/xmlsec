package tree

import "github.com/skarm/xmlsec/internal/lexicon"

// Exact XML/DTD token identities shared by the parser and stream readers.
// Entity names here are distinct from their serialized escaping spellings.
const (
	entityLt   = "lt"
	entityGt   = "gt"
	entityApos = "apos"
	entityQuot = "quot"
)

const (
	dtdDoctypeOpen = "<!DOCTYPE"
	entityAmp      = "amp"
	dtdCDATA       = "CDATA"
	nameUTF8       = lexicon.EncodingUTF8U
)

// Canonical XML writes this exact hexadecimal reference; other serializers may
// use a different lexical spelling for the same character.
const (
	escapeCarriageReturn = "&#xD;"
)
