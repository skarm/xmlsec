package reference

import (
	"context"
	"fmt"
	"slices"

	"github.com/skarm/xmlsec/c14n"
	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/tree"
)

// Options sets the allowed transform chain, processing budgets and optional trusted
// extension processor. Zero-valued numeric limits use [DefaultOptions].
type Options struct {
	// Extension is an optional application-trusted, resource-bounded processor.
	Extension ExtensionProcessor
	// IDRules supplies ID attributes for XPath id(); high-level XMLDSig overrides them consistently.
	IDRules []IDAttributeRule
	// AllowedTransforms selects permitted transform URIs. Empty uses the built-in non-
	// extension set. This low-level processor does not establish application profile policy.
	AllowedTransforms []string
	// MaxTransforms bounds the chain length; the default is eight and the maximum is 64.
	MaxTransforms int
	// MaxInputBytes bounds octet input; the default is 8 MiB.
	MaxInputBytes int
	// MaxOutputBytes bounds emitted bytes; callers must discard partial output on error.
	// The default is 32 MiB.
	MaxOutputBytes int
	// MaxProducedBytes bounds aggregate produced octets; the default is 32 MiB.
	MaxProducedBytes int
	// MaxNodeVisits bounds aggregate node processing work; the default is 2,000,000.
	MaxNodeVisits int
	// XMLLimits applies when octets are parsed as XML. An entirely zero value
	// selects document.DefaultLimits; otherwise all required fields must be valid.
	XMLLimits document.Limits
	// Signature is the exact containing Signature, required for enveloped.
	// It is never rediscovered by ID, tag name, location, or document order.
	Signature document.Element
}

// DefaultOptions returns a fresh value containing the default processing policy.
func DefaultOptions() Options {
	return Options{
		AllowedTransforms: []string{
			EnvelopedSignature, Base64, c14n.Exclusive, c14n.ExclusiveWithComments,
			c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments,
		},
		MaxTransforms: 8, MaxInputBytes: 8 << 20, MaxOutputBytes: 32 << 20,
		MaxProducedBytes: 32 << 20, MaxNodeVisits: 2_000_000, XMLLimits: document.DefaultLimits(),
	}
}

// ValidateTransforms checks configuration and the ENTIRE explicit chain without
// executing transforms or obtaining any resource. Final implicit C14N 1.0 also
// needs permission; that requirement is checked when the final data type is known.
func ValidateTransforms(ts []Transform, opt Options) error {
	opt, err := normalize(opt)
	if err != nil {
		return err
	}

	return validate(context.Background(), ts, opt)
}

func normalize(opt Options) (Options, error) {
	d := DefaultOptions()

	opt.IDRules = cloneRules(opt.IDRules)
	if len(opt.AllowedTransforms) == 0 {
		opt.AllowedTransforms = d.AllowedTransforms
	} else {
		opt.AllowedTransforms = append([]string(nil), opt.AllowedTransforms...)
	}

	if opt.MaxTransforms == 0 {
		opt.MaxTransforms = d.MaxTransforms
	}

	if opt.MaxInputBytes == 0 {
		opt.MaxInputBytes = d.MaxInputBytes
	}

	if opt.MaxOutputBytes == 0 {
		opt.MaxOutputBytes = d.MaxOutputBytes
	}

	if opt.MaxProducedBytes == 0 {
		opt.MaxProducedBytes = d.MaxProducedBytes
	}

	if opt.MaxNodeVisits == 0 {
		opt.MaxNodeVisits = d.MaxNodeVisits
	}

	if opt.XMLLimits == (document.Limits{}) {
		opt.XMLLimits = d.XMLLimits
	}

	if opt.MaxTransforms < 1 || opt.MaxTransforms > 64 || opt.MaxInputBytes < 1 || opt.MaxOutputBytes < 1 || opt.MaxProducedBytes < 1 || opt.MaxNodeVisits < 1 {
		return opt, fmt.Errorf("%w: invalid limits", ErrPolicy)
	}

	if err := opt.XMLLimits.Validate(); err != nil {
		return opt, fmt.Errorf("%w: %w", ErrPolicy, err)
	}

	for _, a := range opt.AllowedTransforms {
		if !isC14N(a) && a != Base64 && a != EnvelopedSignature && !IsExtension(a) {
			return opt, fmt.Errorf("%w: algorithm %q", ErrUnsupported, a)
		}
	}

	return opt, nil
}

func isC14N(a string) bool {
	switch a {
	case c14n.Exclusive, c14n.ExclusiveWithComments, c14n.Canonical10, c14n.Canonical10WithComments, c14n.Canonical11, c14n.Canonical11WithComments:
		return true
	}

	return false
}

func allowed(opt Options, a string) bool {
	return slices.Contains(opt.AllowedTransforms, a)
}

func validate(ctx context.Context, ts []Transform, opt Options) error {
	if len(ts) > opt.MaxTransforms {
		return fmt.Errorf("%w: too many transforms", ErrLimit)
	}

	for i, t := range ts {
		if _, err := checkedTransform(ctx, t); err != nil {
			return &StepError{i, t.Algorithm, err}
		}

		if IsExtension(t.Algorithm) && nilcheck.IsNil(opt.Extension) {
			return &StepError{i, t.Algorithm, fmt.Errorf("%w: no extension processor", ErrPolicy)}
		}

		if !isC14N(t.Algorithm) && t.Algorithm != Base64 && t.Algorithm != EnvelopedSignature && !IsExtension(t.Algorithm) {
			return &StepError{i, t.Algorithm, ErrUnsupported}
		}

		if !allowed(opt, t.Algorithm) {
			return &StepError{i, t.Algorithm, ErrPolicy}
		}

		if len(t.InclusivePrefixes) > 0 && t.Algorithm != c14n.Exclusive && t.Algorithm != c14n.ExclusiveWithComments {
			return &StepError{i, t.Algorithm, fmt.Errorf("%w: InclusiveNamespaces not applicable", ErrInput)}
		}

		if len(t.InclusivePrefixes) > 128 {
			return &StepError{i, t.Algorithm, ErrLimit}
		}

		for _, p := range t.InclusivePrefixes {
			if p != "#default" && (!tree.NCName(p) || p == "xmlns") {
				return &StepError{i, t.Algorithm, fmt.Errorf("%w: inclusive prefix", ErrInput)}
			}
		}
	}

	return nil
}
