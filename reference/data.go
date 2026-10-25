package reference

import (
	"errors"
	"fmt"
	"maps"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/lexicon"
)

const (
	// EnvelopedSignature is the XMLDSig enveloped-signature transform URI.
	EnvelopedSignature = lexicon.TransformEnvelopedSignature
	// Base64 is the XMLDSig Base64 transform URI.
	Base64 = "http://www.w3.org/2000/09/xmldsig#base64"
	// ParseXML labels a diagnostic conversion, NOT a transform algorithm URI.
	ParseXML = "xml-parse"
)

var (
	// ErrInput reports invalid reference input.
	ErrInput = errors.New("invalid reference input")
	// ErrPolicy reports reference policy violation.
	ErrPolicy = errors.New("reference policy violation")
	// ErrLimit reports reference resource limit exceeded.
	ErrLimit = errors.New("reference resource limit exceeded")
	// ErrUnsupported reports unsupported reference operation.
	ErrUnsupported = errors.New("unsupported reference operation")
)

// Kind identifies an octet stream or an XPath node set.
type Kind uint8

const (
	// Invalid identifies an uninitialized or invalid Data value.
	Invalid Kind = iota
	// OctetStream identifies an octet stream.
	OctetStream
	// NodeSet identifies an XPath node set.
	NodeSet
)

// String returns a human-readable name without serializing payload data.
func (k Kind) String() string {
	switch k {
	case OctetStream:
		return "octet-stream"
	case NodeSet:
		return "node-set"
	default:
		return "invalid"
	}
}

// MarshalText represents kinds as readable diagnostic labels, including in JSON.
func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText accepts only diagnostic kind labels. It does not validate or
// authenticate a serialized processing report. An error leaves the receiver
// unchanged, so misspelled labels cannot silently become Invalid.
func (k *Kind) UnmarshalText(text []byte) error {
	if k == nil {
		return fmt.Errorf("%w: nil kind receiver", ErrInput)
	}

	var value Kind

	switch string(text) {
	case "invalid":
		value = Invalid
	case "octet-stream":
		value = OctetStream
	case "node-set":
		value = NodeSet
	default:
		return fmt.Errorf("%w: unknown data kind", ErrInput)
	}

	*k = value

	return nil
}

// Data holds immutable octets or an initialized XPath node set. The zero value is
// invalid, but an empty octet stream or initialized empty node set is valid.
// Octets copies the supplied bytes.
type Data struct {
	kind   Kind
	octets []byte
	nodes  document.NodeSet
}

// Octets copies data into an immutable octet stream.
func Octets(data []byte) Data { return Data{kind: OctetStream, octets: append([]byte(nil), data...)} }

// Nodes wraps a valid immutable node set as transform input.
func Nodes(set document.NodeSet) (Data, error) {
	if !set.Valid() {
		return Data{}, fmt.Errorf("%w: invalid node-set", ErrInput)
	}

	return Data{kind: NodeSet, nodes: set}, nil
}

// Kind returns whether the input is an octet stream, node set or invalid value.
func (d Data) Kind() Kind { return d.kind }

// Size returns the byte count for an octet stream or node count for a node set.
func (d Data) Size() int {
	switch d.kind {
	case OctetStream:
		return len(d.octets)
	case NodeSet:
		return d.nodes.Len()
	default:
		return 0
	}
}

// Bytes returns an owned copy of octets and whether this value is an octet stream.
func (d Data) Bytes() ([]byte, bool) {
	if d.kind != OctetStream {
		return nil, false
	}

	return append([]byte(nil), d.octets...), true
}

// Nodes returns the node set and whether this value contains a valid node set.
func (d Data) Nodes() (document.NodeSet, bool) { return d.nodes, d.kind == NodeSet && d.nodes.Valid() }

// Transform selects an implemented algorithm and its parameters. Algorithm must
// be nonempty. InclusivePrefixes is permitted only for Exclusive C14N.
type Transform struct {
	// Algorithm is the required transform URI; an empty value is rejected.
	Algorithm string `json:"algorithm"`
	// InclusivePrefixes applies only to Exclusive C14N. #default denotes the
	// default namespace; prefixes do not change an explicit node selection.
	InclusivePrefixes []string `json:"inclusive_prefixes,omitempty"`
	// XPath contains one XPath expression or the ordered Filter2 expressions.
	XPath []XPathExpression `json:"xpath,omitempty"`
	// Stylesheet is complete XSLT 1.0 source for an XSLT transform.
	Stylesheet []byte `json:"stylesheet,omitempty"`
}

// Step records a completed transform or implicit conversion and its input and output
// sizes.
type Step struct {
	// Algorithm identifies the transform or implicit conversion.
	Algorithm string `json:"algorithm"`
	// InputSize counts input bytes for OctetStream or selected nodes for NodeSet.
	InputSize int `json:"input_size"`
	// OutputSize counts output bytes for OctetStream or selected nodes for NodeSet.
	OutputSize int `json:"output_size"`
	// InputKind identifies the representation before this step.
	InputKind Kind `json:"input_kind"`
	// OutputKind identifies the representation after this step.
	OutputKind Kind `json:"output_kind"`
	// Implicit marks a required conversion or final C14N step absent from the explicit chain.
	Implicit bool `json:"implicit"`
}

// Report records a completed transform chain without retaining the final output bytes.
type Report struct {
	input            Kind
	size             int
	steps            []Step
	produced         int
	visits           int
	canonicalization string
}

// Size returns the number of final bytes.
func (o *Report) Size() int {
	if o == nil {
		return 0
	}

	return o.size
}

// InputKind returns the original transform input kind.
func (o *Report) InputKind() Kind {
	if o == nil {
		return Invalid
	}

	return o.input
}

// Steps returns an owned copy of the processing trace.
func (o *Report) Steps() []Step {
	if o == nil {
		return nil
	}

	return append([]Step(nil), o.steps...)
}

// ProducedBytes includes intermediate octet outputs as well as the final output.
func (o *Report) ProducedBytes() int {
	if o == nil {
		return 0
	}

	return o.produced
}

// NodeVisits returns the processing node-visit count.
func (o *Report) NodeVisits() int {
	if o == nil {
		return 0
	}

	return o.visits
}

// Canonicalization identifies the final canonicalization step, when present.
func (o *Report) Canonicalization() string {
	if o == nil {
		return ""
	}

	return o.canonicalization
}

// Output retains buffered transform bytes and their processing report.
type Output struct {
	report *Report
	bytes  []byte
}

// Bytes returns an owned copy of the buffered output.
func (o *Output) Bytes() []byte {
	if o == nil {
		return nil
	}

	return append([]byte(nil), o.bytes...)
}

// Size returns the corresponding buffered processing report value.
func (o *Output) Size() int {
	if o == nil {
		return 0
	}

	return o.report.Size()
}

// InputKind returns the corresponding buffered processing report value.
func (o *Output) InputKind() Kind {
	if o == nil {
		return Invalid
	}

	return o.report.InputKind()
}

// Steps returns the corresponding buffered processing report value.
func (o *Output) Steps() []Step {
	if o == nil {
		return nil
	}

	return o.report.Steps()
}

// ProducedBytes returns the corresponding buffered processing report value.
func (o *Output) ProducedBytes() int {
	if o == nil {
		return 0
	}

	return o.report.ProducedBytes()
}

// NodeVisits returns the corresponding buffered processing report value.
func (o *Output) NodeVisits() int {
	if o == nil {
		return 0
	}

	return o.report.NodeVisits()
}

// Canonicalization returns the corresponding buffered processing report value.
func (o *Output) Canonicalization() string {
	if o == nil {
		return ""
	}

	return o.report.Canonicalization()
}

// StepError identifies a failed transform and preserves its error for errors.Is
// and errors.As. Index is zero-based; -1 identifies the final implicit conversion
// or raw output validation.
type StepError struct {
	// Index is zero-based; -1 identifies implicit final conversion or raw output validation.
	Index int
	// Algorithm identifies the transform or conversion that failed.
	Algorithm string
	// Err is the underlying error exposed by Unwrap.
	Err error
}

// Error returns the diagnostic error message.
func (e *StepError) Error() string {
	return fmt.Sprintf("reference step %d (%s): %v", e.Index, e.Algorithm, e.Err)
}

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *StepError) Unwrap() error { return e.Err }

// CloneTransforms returns a deep copy of transform parameters, including namespace maps
// and stylesheet bytes.
func CloneTransforms(ts []Transform) []Transform {
	out := append([]Transform(nil), ts...)

	for i := range out {
		out[i].InclusivePrefixes = append([]string(nil), out[i].InclusivePrefixes...)
		out[i].Stylesheet = append([]byte(nil), out[i].Stylesheet...)
		out[i].XPath = append([]XPathExpression(nil), out[i].XPath...)

		for j := range out[i].XPath {
			ns := make(map[string]string, len(out[i].XPath[j].Namespaces))
			maps.Copy(ns, out[i].XPath[j].Namespaces)
			out[i].XPath[j].Namespaces = ns
		}
	}

	return out
}
