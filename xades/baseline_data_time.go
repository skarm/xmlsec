package xades

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
	"github.com/skarm/xmlsec/internal/transformxml"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
	"github.com/skarm/xmlsec/timestamp"
	"github.com/skarm/xmlsec/xmldsig"
)

// DataTimestampProperty supplies a pre-existing RFC3161 content timestamp.
// When Individual is true, ObjectReferences selects ordered Reference URIs.
// Otherwise, the timestamp covers direct SignedInfo data References in their
// signed order. Token authority is checked separately.
type DataTimestampProperty struct {
	// Individual selects IndividualDataObjectsTimeStamp. False selects
	// AllDataObjectsTimeStamp.
	Individual bool
	// ObjectReferences lists ordered Reference fragment URIs for an individual timestamp.
	ObjectReferences []string
	// Canonicalization selects the timestamp input transform. An empty algorithm selects
	// Canonical XML 1.0.
	Canonicalization reference.Transform
	// TokenDER contains the complete RFC 3161 CMS timestamp token in DER.
	TokenDER []byte
}

// DataTimestampLimits bounds parsed content timestamp containers and replay.
// Zero fields select the defaults documented below.
type DataTimestampLimits struct {
	// MaxTimestamps bounds parsed content timestamp tokens. Zero selects 16. The maximum is
	// 64.
	MaxTimestamps int
	// MaxTokenBytes bounds each token's DER size. Zero selects 4 MiB. The maximum is 16
	// MiB.
	MaxTokenBytes int
	// MaxInputBytes bounds replayed timestamp input. Zero selects 16 MiB. The maximum is 64
	// MiB.
	MaxInputBytes int
}

// DataTimestamp is a signed content-timestamp claim bound to exact authenticated
// References. Token parses RFC3161 syntax; it has not acquired TSA trust or PoE.
type DataTimestamp struct {
	element     document.Element
	method      reference.Transform
	references  []xmldsig.ReferenceResult
	identifiers []string
	token       *timestamp.Token
	maximum     int
}

// Element returns the immutable content timestamp property element.
func (value DataTimestamp) Element() document.Element { return value.element }

// TokenDER returns an owned copy of the unverified timestamp token DER, or nil when
// absent.
func (value DataTimestamp) TokenDER() []byte {
	if value.token == nil {
		return nil
	}

	return value.token.DER()
}

// Token returns the immutable parsed timestamp token. Its TSA trust has not been
// established.
func (value DataTimestamp) Token() *timestamp.Token { return value.token }

// CanonicalizationMethod returns the algorithm URI used for timestamp input
// canonicalization.
func (value DataTimestamp) CanonicalizationMethod() string { return value.method.Algorithm }

// Canonicalization returns an independent copy of the timestamp input transform and its
// parameters.
func (value DataTimestamp) Canonicalization() reference.Transform {
	return reference.CloneTransforms([]reference.Transform{value.method})[0]
}

// ObjectReferences returns an independent slice of ordered individual Reference URIs.
// All-data timestamps have no individual URI list.
func (value DataTimestamp) ObjectReferences() []string { return slices.Clone(value.identifiers) }

// WriteImprintInput constructs EN319132-1 5.2.8 input in exact Reference/Include
// order. Each reference source/program is replayed once; the original signed
// digest and resource identity are rechecked before success. On any error the
// caller must discard all written bytes. This is not TSA authentication.
func (value DataTimestamp) WriteImprintInput(ctx context.Context, dst io.Writer) (int64, error) {
	if ctx == nil || nilcheck.IsNil(dst) || value.token == nil || value.maximum <= 0 {
		return 0, ErrProfile
	}

	writer := streamio.Writer{Context: ctx, Target: dst, Limit: int64(value.maximum), LimitError: ErrProfile}
	for _, ref := range value.references {
		if _, err := ref.WriteCanonicalizedInput(ctx, &writer, value.method); err != nil {
			return writer.Written, err
		}
	}

	return writer.Written, ctx.Err()
}

// DataTimestamps returns signed content claims. Their RFC3161 signatures, TSA
// trust and temporal order require the separate evidence validation workflow.
func (r *BaselineResult) DataTimestamps() []DataTimestamp {
	if r == nil {
		return nil
	}

	return slices.Clone(r.dataTimestamps)
}

func normalizeDataTimestampLimits(options DataTimestampLimits) (DataTimestampLimits, error) {
	if options.MaxTimestamps == 0 {
		options.MaxTimestamps = 16
	}

	if options.MaxTokenBytes == 0 {
		options.MaxTokenBytes = 4 << 20
	}

	if options.MaxInputBytes == 0 {
		options.MaxInputBytes = 16 << 20
	}

	if options.MaxTimestamps < 1 || options.MaxTimestamps > 64 || options.MaxTokenBytes < 1 || options.MaxTokenBytes > 16<<20 || options.MaxInputBytes < 1 || options.MaxInputBytes > 64<<20 {
		return options, ErrProfile
	}

	return options, nil
}

func parseBaselineDataTimestamp(ctx context.Context, element document.Element, verified *xmldsig.SignatureResult, limits DataTimestampLimits, options BaselineVerifyOptions) (DataTimestamp, error) {
	out := DataTimestamp{element: element, method: reference.Transform{Algorithm: c14n.Canonical10}, maximum: limits.MaxInputBytes}
	if baselineAttrs(element, nil, "Id") != nil {
		return out, ErrProfile
	}

	values, err := baselineContent(element)
	if err != nil || len(values) == 0 {
		return out, ErrProfile
	}

	at := 0
	for at < len(values) && values[at].Name() == name("Include") {
		include := values[at]
		if baselineAttrs(include, []string{"URI", "referencedData"}) != nil {
			return out, ErrProfile
		}

		if _, err := children(include); err != nil {
			return out, err
		}

		truth := strings.Trim(localAttribute(include, "referencedData"), " \t\r\n")
		if truth != "true" && truth != "1" {
			return out, ErrProfile
		}

		if len(out.identifiers) >= 256 {
			return out, ErrProfile
		}

		out.identifiers = append(out.identifiers, localAttribute(include, "URI"))
		at++
	}

	individual := element.Name() == name("IndividualDataObjectsTimeStamp")
	if individual != (len(out.identifiers) > 0) {
		return out, ErrProfile
	}

	if at < len(values) && values[at].Name() == ds(lexicon.DSigElementCanonicalizationMethod) {
		_, node := tree.Unwrap(values[at])

		out.method, err = transformxml.ParseCanonical(node, lexicon.DSigElementCanonicalizationMethod)
		if err != nil {
			return out, errors.Join(ErrProfile, err)
		}

		at++
	}

	if at != len(values)-1 {
		return out, ErrProfile
	}

	token := values[at]
	if token.Name() != name("EncapsulatedTimeStamp") || baselineAttrs(token, nil, "Id", attributeEncoding) != nil {
		return out, ErrProfile
	}

	encoding := localAttribute(token, attributeEncoding)
	if encoding != "" && encoding != encodingDER && encoding != encodingBER {
		return out, ErrProfile
	}

	raw, err := decodeElementBase64(ctx, token, limits.MaxTokenBytes*2, limits.MaxTokenBytes)
	if err != nil {
		return out, err
	}

	out.token, err = timestamp.ParseToken(ctx, raw)
	if err != nil {
		return out, errors.Join(ErrTimestamp, err)
	}

	if err := out.bindReferences(verified, individual, options); err != nil {
		return out, err
	}

	return out, nil
}

func buildBaselineDataTimestamp(ctx context.Context, value DataTimestampProperty, limits DataTimestampLimits) (*tree.Node, error) {
	local := "AllDataObjectsTimeStamp"
	if value.Individual {
		local = "IndividualDataObjectsTimeStamp"
	}

	if len(value.ObjectReferences) > 256 || value.Individual != (len(value.ObjectReferences) > 0) || len(value.TokenDER) == 0 || len(value.TokenDER) > limits.MaxTokenBytes {
		return nil, ErrProfile
	}

	if _, err := timestamp.ParseToken(ctx, value.TokenDER); err != nil {
		return nil, errors.Join(ErrTimestamp, err)
	}

	node := xnode(local)

	for _, identifier := range value.ObjectReferences {
		if !baselineURI(identifier) {
			return nil, ErrProfile
		}

		include := xnode("Include")
		attr(include, "URI", identifier)
		attr(include, "referencedData", "true")
		add(node, include)
	}

	method := value.Canonicalization
	if method.Algorithm != "" {
		canonical := dsnode(lexicon.DSigElementCanonicalizationMethod)
		attr(canonical, "Algorithm", method.Algorithm)

		if err := transformxml.AppendParameters(ctx, canonical, method); err != nil {
			return nil, err
		}

		if _, err := transformxml.ParseCanonical(canonical, lexicon.DSigElementCanonicalizationMethod); err != nil {
			return nil, err
		}

		add(node, canonical)
	} else if len(method.InclusivePrefixes)+len(method.XPath)+len(method.Stylesheet) != 0 {
		return nil, ErrProfile
	}

	leaf(node, "EncapsulatedTimeStamp", base64.StdEncoding.EncodeToString(value.TokenDER))

	return node, nil
}

func (value *DataTimestamp) bindReferences(verified *xmldsig.SignatureResult, individual bool, options BaselineVerifyOptions) error {
	refs, err := baselineDataReferences(verified)
	if err != nil {
		return err
	}

	if individual {
		for _, identifier := range value.identifiers {
			key, err := baselineReferenceKey(identifier, value.element, options)
			if err != nil {
				return err
			}

			ref, found := refs[key]
			if !found || ref.result.Type() == SignedPropertiesType {
				return ErrProfile
			}

			value.references = append(value.references, ref.result)
		}
	} else {
		si, err := childNamed(verified.Signature(), ds(lexicon.DSigElementSignedInfo))
		if err != nil {
			return err
		}

		index := 0

		for _, element := range si.Children() {
			if element.Name() != ds(lexicon.DSigElementReference) {
				continue
			}

			ref := verified.References()[index]
			index++

			if ref.Type() == SignedPropertiesType {
				continue
			}

			value.references = append(value.references, ref)
			value.identifiers = append(value.identifiers, "#"+localAttribute(element, "Id"))
		}
	}

	if len(value.references) == 0 {
		return ErrProfile
	}

	return nil
}
