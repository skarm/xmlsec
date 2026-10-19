package xmlenc

import (
	"bytes"
	"context"
	"unicode/utf8"

	norm "github.com/skarm/xmlsec/internal/normalization"

	"github.com/skarm/xmlsec/document"
)

// XML Encryption 1.1 sections 4.2--4.3 require Type #Element to be a single
// element serialized as UTF-8 in NFC. Checking, rather than normalizing, keeps
// plaintext semantics and embedded XML signatures unchanged. NFC tables are
// supplied by golang.org/x/text/unicode/norm (Copyright 2009 The Go Authors),
// pinned in go.mod/go.sum. Its BSD-3-Clause license is in licenses/BSD-3-Clause-Go.txt.
func elementEncoding(ctx context.Context, raw []byte) error {
	if err := contentEncoding(ctx, raw); err != nil {
		return err
	}

	if len(raw) == 0 || raw[0] != '<' || raw[len(raw)-1] != '>' || bytes.HasPrefix(raw, []byte("<?")) {
		return ErrFormat
	}

	return nil
}

// Content can be empty or mixed XML, but uses the same UTF-8/NFC serialization.
func contentEncoding(ctx context.Context, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !utf8.Valid(raw) {
		return ErrFormat
	}

	normal, err := norm.IsNormal(ctx, norm.NFC, raw)
	if err != nil {
		return err
	}

	if !normal {
		return ErrFormat
	}

	return ctx.Err()
}

func singleElement(doc *document.Document) bool {
	if doc == nil || !doc.Root().Valid() {
		return false
	}

	children := doc.Node().Children()

	return len(children) == 1 && children[0].Same(doc.Root().Node())
}
