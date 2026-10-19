package xmldsig

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/keyinfo"
	"github.com/skarm/xmlsec/reference"
)

// ErrKeyInfoTrust reports KeyInfo did not select an explicitly trusted key.
var ErrKeyInfoTrust = errors.New("KeyInfo did not select an explicitly trusted key")

// TrustedKeySelector MUST implement an application trust decision (e.g. a pin
// for the expected partner, or PKIX plus its required subject/role constraints).
// It returns the index of the permitted candidate, or an error. Merely choosing
// the first certificate/key, or trusting KeyName, makes an unsafe selector.
// Certificates/CRLs/names in the result are untrusted; parsing has not checked
// chain relationships, certificate selectors, validity, revocation or identity.
// The callback is called once, BEFORE signed resources can be read. All mutable
// key data obtained from Candidate are copies; the selected index is used to
// load a fresh key afterwards, not a key object mutated by the callback.
type TrustedKeySelector func(context.Context, *keyinfo.Result) (int, error)

// KeyInfoVerifyOptions sets signature and KeyInfo parsing policy and requires an
// application trust selector.
type KeyInfoVerifyOptions struct {
	Signature SignatureOptions
	KeyInfo   keyinfo.Options
	// SelectTrustedKey is mandatory; there is no permissive default.
	SelectTrustedKey TrustedKeySelector
}

// VerifySignatureWithKeyInfo explicitly opts into key discovery. The existing
// VerifySignature API still uses ONLY its caller-supplied key, never KeyInfo.
//
// Order: structural/algorithm preflight; bounded KeyInfo discovery; explicit trust
// selection; SignatureValue; every required Reference and requested coverage.
// Remote KeyInfo discovery, when separately enabled, necessarily precedes
// cryptographic authentication; it has an independent allowlist and limits.
// A successful result authenticates signed data with the chosen trusted key,
// NOT all unsigned KeyInfo selectors/metadata. This is not full KeyInfo schema
// or PKIX validation. Unsupported KeyInfo forms fail closed.
func VerifySignatureWithKeyInfo(ctx context.Context, doc *document.Document, selected document.Element, opt KeyInfoVerifyOptions) (*SignatureResult, error) {
	if opt.SelectTrustedKey == nil {
		return nil, ErrKeyInfoTrust
	}
	// Freeze reference/algorithm policies before invoking user code. Preserve the
	// nil vs empty ExpectedURIs distinction: empty explicitly means invalid policy.
	sigOpt := cloneSignatureOptions(opt.Signature)
	report := &VerificationReport{}

	plan, err := prepareCore(ctx, doc, selected, sigOpt, false, report)
	if err != nil {
		return nil, err
	}

	if _, mac := macHash(plan.method); mac {
		return nil, fmt.Errorf("%w: HMAC does not use public-key discovery", ErrKey)
	}

	var ki *tree.Node

	for _, n := range plan.sig.Children {
		if isDS(n, "KeyInfo") {
			ki = n
			break
		}
	}

	if ki == nil {
		return nil, fmt.Errorf("%w: KeyInfo absent", ErrKeyInfoTrust)
	}
	// The KeyInfo resolver and signature resolver must agree on the application's
	// ID rules, and any collisions across recognized attributes are fatal.
	sigOpt.IDAttribute, err = normalizeID(sigOpt.IDAttribute)
	if err != nil {
		return nil, err
	}

	keyOpt := opt.KeyInfo
	keyOpt.AdditionalIDRules = append(cloneIDRules(keyOpt.AdditionalIDRules), coreIDRules(sigOpt)...)

	info, err := keyinfo.Parse(ctx, doc, tree.Wrap(doc, ki), keyOpt)
	if err != nil {
		return nil, fmt.Errorf("KeyInfo discovery: %w", err)
	}

	index, err := opt.SelectTrustedKey(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInfoTrust, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := info.CheckKeyDeclarations(index); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInfoTrust, err)
	}

	candidates := info.Candidates()
	// CheckKeyDeclarations also checks index bounds.
	key, err := candidates[index].PublicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyInfoTrust, err)
	}

	return VerifySignature(ctx, doc, selected, key, sigOpt)
}

func cloneIDRules(a []reference.IDAttributeRule) []reference.IDAttributeRule {
	out := slices.Clone(a)
	for i := range out {
		out[i].Elements = slices.Clone(a[i].Elements)
	}

	return out
}

func cloneSignatureOptions(o SignatureOptions) SignatureOptions {
	o.Policy.AllowedSignatureMethods = slices.Clone(o.Policy.AllowedSignatureMethods)
	o.Policy.AllowedDigestMethods = slices.Clone(o.Policy.AllowedDigestMethods)
	o.AllowedCanonicalizationMethods = slices.Clone(o.AllowedCanonicalizationMethods)
	o.Processing.AllowedTransforms = slices.Clone(o.Processing.AllowedTransforms)
	o.Processing.IDRules = cloneIDRules(o.Processing.IDRules)
	o.RequiredElements = slices.Clone(o.RequiredElements)
	o.ExpectedURIs = slices.Clone(o.ExpectedURIs)

	o.AdditionalIDRules = cloneIDRules(o.AdditionalIDRules)
	if o.External != nil {
		x := *o.External
		x.AllowedURIs = slices.Clone(x.AllowedURIs)
		o.External = &x
	}

	return o
}
