package reference

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
)

// ProgramFingerprint identifies exact approved extension parameters. Runtime Here
// handles are excluded; XSLT stylesheet bytes are canonicalized. This is an
// allowlist key, not authentication of the signature or document.
func ProgramFingerprint(t Transform) (string, error) {
	if !IsExtension(t.Algorithm) {
		return "", ErrUnsupported
	}

	ctx := context.Background()

	doc, err := checkedTransform(ctx, t)
	if err != nil {
		return "", err
	}
	// Only mutable XPath maps need copying. XSLT source is borrowed during
	// its single parse and is never serialized as the fingerprint payload.
	t.Stylesheet = nil
	t = CloneTransforms([]Transform{t})[0]

	for i := range t.XPath {
		t.XPath[i].Here = document.Element{}
		t.XPath[i].Namespaces["xml"] = document.XMLNamespace
	}

	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	if doc == nil {
		_, _ = hash.Write(b)
	} else {
		// Stylesheet is the last JSON field. Preserve the existing fingerprint
		// bytes exactly while streaming canonical XML through JSON's Base64 form.
		_, _ = hash.Write(b[:len(b)-1])
		_, _ = io.WriteString(hash, `,"stylesheet":"`)

		encoder := base64.NewEncoder(base64.StdEncoding, hash)
		if err := c14n.WriteDocument(ctx, encoder, doc, c14n.Options{Algorithm: c14n.Canonical10}); err != nil {
			return "", err
		}

		if err := encoder.Close(); err != nil {
			return "", err
		}

		_, _ = io.WriteString(hash, `"}`)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
