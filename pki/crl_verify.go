package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"

	"github.com/skarm/xmlsec/internal/der"
)

// CRLOptions controls the offline CRL algorithm. Zero enables supplied deltas.
// A FreshestCRL advertisement then requires a current applicable supplied delta;
// no resource is fetched. NextUpdate is always an exclusive upper boundary.
type CRLOptions struct {
	signerDepth int
	// DisableDeltaCRLs selects RFC5280's use-deltas=false input explicitly.
	DisableDeltaCRLs bool
	// MaxAge bounds a CRL lacking NextUpdate; default24h, maximum30d.
	MaxAge time.Duration
}

func normalizeCRLOptions(o CRLOptions) (CRLOptions, error) {
	if o.signerDepth == 0 {
		o.signerDepth = 10
	}

	if o.MaxAge == 0 {
		o.MaxAge = 24 * time.Hour
	}

	if o.MaxAge <= 0 || o.MaxAge > 30*24*time.Hour {
		return o, ErrPolicy
	}

	return o, nil
}

type (
	crlWorkBudget        struct{ checks int }
	crlAuthenticationKey struct {
		anchor [32]byte
		leaf   [32]byte
	}
)

type authenticatedCRL struct {
	list   *parsedCRL
	signer *x509.Certificate
}

type completeCRLView struct {
	base  *authenticatedCRL
	delta *authenticatedCRL
	this  time.Time
}

func parseCRLs(ctx context.Context, ders [][]byte) ([]*parsedCRL, error) {
	out := make([]*parsedCRL, 0, len(ders))
	work := &crlWorkBudget{}

	for _, raw := range ders {
		list, err := parseCRL(ctx, raw)
		if err != nil {
			return nil, err
		}

		list.work = work
		list.authentication = make(map[crlAuthenticationKey]*x509.Certificate)
		out = append(out, list)
	}

	return out, ctx.Err()
}

func checkChainCRLs(ctx context.Context, chain []*x509.Certificate, lists []*parsedCRL, at time.Time, options ...CRLOptions) error {
	opts := CRLOptions{}
	if len(options) > 0 {
		opts = options[0]
	}

	opts, err := normalizeCRLOptions(opts)
	if err != nil {
		return err
	}

	groups, err := authenticateCRLs(ctx, chain, lists, at, opts.signerDepth)
	if err != nil {
		return err
	}

	for index := 0; index+1 < len(chain); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := checkCertificateCRLs(ctx, chain[index], chain, groups, at, opts); err != nil {
			return fmt.Errorf("%w: chain index%d", err, index)
		}
	}

	return ctx.Err()
}

func authenticateCRLs(ctx context.Context, chain []*x509.Certificate, lists []*parsedCRL, at time.Time, maximumDepth int) (map[string][]*authenticatedCRL, error) {
	authentication, err := newCRLAuthentication(ctx, chain, lists, at, maximumDepth)
	if err != nil {
		return nil, err
	}

	groups := make(map[string][]*authenticatedCRL)

	for _, list := range lists {
		signer, err := authentication.authenticate(ctx, list)
		if err != nil {
			return nil, err
		}

		if signer == nil {
			continue
		}

		key := list.issuerKey + "/" + string(list.scope.raw) + "/" + string(signer.RawSubjectPublicKeyInfo)
		groups[key] = append(groups[key], &authenticatedCRL{list: list, signer: signer})
	}

	return groups, ctx.Err()
}

type crlAuthentication struct {
	candidates    []*x509.Certificate
	roots         *x509.CertPool
	intermediates *x509.CertPool
	anchor        *x509.Certificate
	key           crlAuthenticationKey
	at            time.Time
	maximumDepth  int
}

func newCRLAuthentication(ctx context.Context, chain []*x509.Certificate, lists []*parsedCRL, at time.Time, maximumDepth int) (*crlAuthentication, error) {
	candidates, err := crlCandidates(chain, lists)
	if err != nil {
		return nil, err
	}

	anchor := chain[len(chain)-1]

	anchorView, err := normalizedCertificate(ctx, anchor)
	if err != nil {
		return nil, err
	}

	auth := &crlAuthentication{
		candidates:    candidates,
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		anchor:        anchor,
		at:            at,
		maximumDepth:  maximumDepth,
		key:           crlAuthenticationKey{anchor: sha256.Sum256(anchor.Raw), leaf: sha256.Sum256(chain[0].Raw)},
	}
	auth.roots.AddCert(anchorView)

	for _, candidate := range candidates {
		view, err := normalizedCertificate(ctx, candidate)
		if err != nil {
			return nil, err
		}

		auth.intermediates.AddCert(view)
	}

	return auth, nil
}

func (a *crlAuthentication) authenticate(ctx context.Context, list *parsedCRL) (*x509.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if list.this.After(a.at) {
		return nil, nil
	}

	if signer, found := list.authentication[a.key]; found {
		return signer, nil
	}

	for _, signer := range a.candidates {
		authorized, err := a.authorizedSigner(ctx, list, signer)
		if err != nil {
			return nil, err
		}

		if authorized {
			list.authentication[a.key] = signer
			return signer, nil
		}
	}
	// Only completed ordinary negative authentication is cached; cancellation
	// and configured work limits leave the entry absent.
	list.authentication[a.key] = nil

	return nil, nil
}

func (a *crlAuthentication) authorizedSigner(ctx context.Context, list *parsedCRL, signer *x509.Certificate) (bool, error) {
	matches, err := list.signerMatches(ctx, signer)
	if err != nil || !matches {
		return false, err
	}

	if list.work == nil {
		return false, ErrEvidence
	}

	list.work.checks++
	if list.work.checks > 4096 {
		return false, fmt.Errorf("%w: %w: CRL signature work limit", ErrPolicy, ErrLimit)
	}

	signatureMatches := list.verifySignature(signer.PublicKey) == nil
	if !signatureMatches {
		return false, nil
	}

	view, err := normalizedCertificate(ctx, signer)
	if err != nil {
		return false, err
	}

	paths, err := view.Verify(x509.VerifyOptions{
		Roots:                     a.roots,
		Intermediates:             a.intermediates,
		CurrentTime:               a.at,
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		MaxConstraintComparisions: 100000,
	})

	return err == nil && validCRLSignerPaths(paths, a.anchor, a.maximumDepth), ctx.Err()
}

func crlCandidates(chain []*x509.Certificate, lists []*parsedCRL) ([]*x509.Certificate, error) {
	candidates := append([]*x509.Certificate(nil), chain...)

	seen := make(map[[32]byte]struct{})
	for _, cert := range candidates {
		seen[sha256.Sum256(cert.Raw)] = struct{}{}
	}

	for _, list := range lists {
		for _, raw := range list.candidates {
			digest := sha256.Sum256(raw)
			if _, exists := seen[digest]; exists {
				continue
			}

			cert, err := parseBorrowedCertificate(raw)
			if err != nil {
				return nil, err
			}

			seen[digest] = struct{}{}

			candidates = append(candidates, cert)
		}
	}

	sort.Slice(candidates, func(i, j int) bool { return bytes.Compare(candidates[i].Raw, candidates[j].Raw) < 0 })

	return candidates, nil
}

func (l *parsedCRL) signerMatches(ctx context.Context, signer *x509.Certificate) (bool, error) {
	name, err := canonicalNameKey(ctx, signer.RawSubject)
	if err != nil || l.issuerKey != name {
		return false, err
	}

	if len(l.authorityKeyID) > 0 && len(signer.SubjectKeyId) > 0 && !bytes.Equal(l.authorityKeyID, signer.SubjectKeyId) {
		return false, nil
	}

	if signer.Version == 3 && signer.KeyUsage&x509.KeyUsageCRLSign == 0 || signer.KeyUsage != 0 && signer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return false, nil
	}

	if l.authoritySerial == nil {
		return true, nil
	}

	issuers, err := certificateIssuerNames(ctx, signer)
	if err != nil {
		return false, err
	}

	return signer.SerialNumber.Cmp(l.authoritySerial) == 0 && intersectCRLNames(l.authorityIssuers, issuers), nil
}

func validCRLSignerPaths(paths [][]*x509.Certificate, anchor *x509.Certificate, maximumDepth int) bool {
	for _, path := range paths {
		if len(path) > maximumDepth || !bytes.Equal(path[len(path)-1].Raw, anchor.Raw) {
			continue
		}

		valid := true

		for i, cert := range path {
			if allowedPublicKey(cert.PublicKey) != nil || i+1 < len(path) && !allowedSignature(cert.SignatureAlgorithm) {
				valid = false
				break
			}
		}

		if valid {
			return true
		}
	}

	return false
}

func checkCRLSequence(group []*authenticatedCRL) error {
	sort.Slice(group, func(i, j int) bool { return compareCRLOrder(group[i].list, group[j].list) < 0 })

	if err := checkSimultaneousCRLNumbers(group); err != nil {
		return err
	}

	numbered := map[string]*parsedCRL{}

	var previous *parsedCRL

	for _, auth := range group {
		list := auth.list
		if list.number == nil {
			continue
		}

		kind := "complete/"
		if list.base != nil {
			kind = "delta/"
		}

		key := kind + list.number.String()
		if old := numbered[key]; old != nil && !bytes.Equal(old.tbs, list.tbs) {
			return fmt.Errorf("%w: conflicting CRLs with the same number", ErrEvidence)
		}

		numbered[key] = list
		if previous != nil {
			comparison := list.number.Cmp(previous.number)
			if list.this.After(previous.this) && comparison <= 0 {
				return fmt.Errorf("%w: non-monotonic CRL numbers", ErrEvidence)
			}
		}

		previous = list
	}

	return nil
}

func crlFresh(list *parsedCRL, at time.Time, o CRLOptions) bool {
	expiry := list.next
	if expiry.IsZero() {
		expiry = list.this.Add(o.MaxAge)
	}

	return !list.this.After(at) && at.Before(expiry)
}

func certificateCRLPoints(ctx context.Context, cert *x509.Certificate) ([]crlDistributionPoint, bool, error) {
	points := make([]crlDistributionPoint, 0, 1)
	freshest := false

	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.31" {
			var err error

			points, err = parseCRLDistributionPoints(ctx, ext.Value)
			if err != nil {
				return nil, false, err
			}
		}

		if ext.Id.String() == "2.5.29.46" {
			if ext.Critical {
				return nil, false, ErrEvidence
			}

			if _, err := parseCRLDistributionPoints(ctx, ext.Value); err != nil {
				return nil, false, err
			}

			freshest = true
		}
	}
	// RFC5280§6.3.3 fallback also considers complete issuer CRLs not named by a DP.
	names, err := certificateIssuerNames(ctx, cert)
	if err != nil {
		return nil, false, err
	}

	fallback := crlDistributionPoint{names: names, reasons: allCRLReasons}

	return append(points, fallback), freshest, nil
}

func applicableCRLScope(ctx context.Context, cert *x509.Certificate, list *parsedCRL, point crlDistributionPoint) (crlReasonMask, error) {
	scope := list.scope
	if scope.onlyAttribute || scope.onlyUser && cert.IsCA || scope.onlyCA && !cert.IsCA || (scope.onlyUser || scope.onlyCA) && cert.Version < 3 {
		return 0, nil
	}

	if len(point.issuer) > 0 {
		if !scope.indirect || !intersectCRLNames(point.issuer, []crlGeneralName{{tag: 4, value: list.issuer, key: list.issuerKey}}) {
			return 0, nil
		}
	} else if certIssuer, err := canonicalNameKey(ctx, cert.RawIssuer); err != nil {
		return 0, err
	} else if list.issuerKey != certIssuer {
		return 0, nil
	}

	scopeNames, err := crlPointNames(ctx, scope.crlDistributionPoint, list.issuer)
	if err != nil {
		return 0, err
	}

	if len(scopeNames) > 0 {
		names, err := crlPointNames(ctx, point, cert.RawIssuer)
		if err != nil {
			return 0, err
		}

		if len(names) == 0 {
			names = point.issuer
		}

		if !intersectCRLNames(scopeNames, names) {
			return 0, nil
		}
	}

	return scope.reasons & point.reasons, nil
}

func findCRLEntry(ctx context.Context, list *parsedCRL, cert *x509.Certificate) (*crlEntry, error) {
	wanted, err := crlDirectoryName(ctx, cert.RawIssuer)
	if err != nil {
		return nil, err
	}

	for index := range list.entries {
		if index&255 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}

		entry := &list.entries[index]
		if entry.serial.Cmp(cert.SerialNumber) == 0 && intersectCRLNames(entry.issuers, []crlGeneralName{wanted}) {
			return entry, nil
		}
	}

	return nil, nil
}

func viewCRLEntry(ctx context.Context, view completeCRLView, cert *x509.Certificate) (*crlEntry, error) {
	if view.delta != nil {
		entry, err := findCRLEntry(ctx, view.delta.list, cert)
		if err != nil {
			return nil, err
		}

		if entry != nil {
			if entry.reason == 8 {
				return nil, nil
			}

			return entry, nil
		}
	}

	return findCRLEntry(ctx, view.base.list, cert)
}

func recordCRLAssertion(ctx context.Context, auth *authenticatedCRL, cert, issuer *x509.Certificate, at time.Time) (*VerifiedEvidence, error) {
	target := sha256.Sum256(cert.Raw)
	signer := sha256.Sum256(auth.signer.Raw)

	issuerKey := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	for _, item := range auth.list.authenticated {
		if item.target == target && item.signer == signer && item.issuer == issuerKey && item.validation.Equal(at) {
			return item, nil
		}
	}

	item := newCRLEvidence(auth.list, cert, issuer, auth.signer, at)

	entry, err := findCRLEntry(ctx, auth.list, cert)
	if err != nil {
		return nil, err
	}

	if entry != nil {
		item.status = "revoked"
		item.revoked = entry.revoked
		item.invalidity = entry.invalidity

		item.reason = entry.reason
		if entry.reason == 8 {
			item.status = "remove-from-crl"
		}
	}

	auth.list.authenticated = append(auth.list.authenticated, item)

	return item, nil
}

func useCRLAssertion(ctx context.Context, view completeCRLView, cert, issuer *x509.Certificate, at time.Time, mask crlReasonMask) error {
	base, err := recordCRLAssertion(ctx, view.base, cert, issuer, at)
	if err != nil {
		return err
	}

	baseApplied := *base
	baseApplied.coverage = mask

	view.base.list.used = append(view.base.list.used, &baseApplied)
	if view.delta != nil {
		delta, err := recordCRLAssertion(ctx, view.delta, cert, issuer, at)
		if err != nil {
			return err
		}

		composite := *delta
		composite.coverage = mask
		composite.dependencies = []string{base.FingerprintSHA256()}
		view.delta.list.used = append(view.delta.list.used, &composite)
	}

	return nil
}

func checkCertificateCRLs(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate, groups map[string][]*authenticatedCRL, at time.Time, o CRLOptions) error {
	points, freshest, err := certificateCRLPoints(ctx, cert)
	if err != nil {
		return err
	}

	issuer := chain[len(chain)-1]
	for index := 0; index+1 < len(chain); index++ {
		if bytes.Equal(chain[index].Raw, cert.Raw) {
			issuer = chain[index+1]
			break
		}
	}

	var covered crlReasonMask
	// Stable group ordering makes diagnostics and future evidence references
	// independent of Go map iteration and the caller's evidence order.
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		mask, err := checkCRLGroup(ctx, groups[key], points, cert, issuer, at, o, freshest)
		if err != nil {
			return err
		}

		covered |= mask
	}

	if covered != allCRLReasons {
		return ErrUnavailable
	}

	return ctx.Err()
}

func recordCRLGroup(ctx context.Context, group []*authenticatedCRL, points []crlDistributionPoint, cert, issuer *x509.Certificate, at time.Time) error {
	for _, auth := range group {
		for _, point := range points {
			mask, err := applicableCRLScope(ctx, cert, auth.list, point)
			if err != nil {
				return err
			}

			if mask == 0 {
				continue
			}

			if _, err := recordCRLAssertion(ctx, auth, cert, issuer, at); err != nil {
				return err
			}

			break
		}
	}

	return nil
}

func checkCRLGroup(ctx context.Context, group []*authenticatedCRL, points []crlDistributionPoint, cert, issuer *x509.Certificate, at time.Time, o CRLOptions, freshest bool) (crlReasonMask, error) {
	if err := recordCRLGroup(ctx, group, points, cert, issuer, at); err != nil {
		return 0, err
	}

	views, err := constructCRLViews(ctx, group, at, o)
	if err != nil {
		return 0, err
	}

	var covered crlReasonMask

	for _, point := range points {
		mask, err := checkCRLPointViews(ctx, views, point, cert, issuer, at, o, freshest)
		if err != nil {
			return 0, err
		}

		covered |= mask
	}

	return covered, nil
}

func checkCRLPointViews(ctx context.Context, views []completeCRLView, point crlDistributionPoint, cert, issuer *x509.Certificate, at time.Time, o CRLOptions, freshest bool) (crlReasonMask, error) {
	for _, view := range views {
		if !o.DisableDeltaCRLs && (freshest || len(view.base.list.freshest) > 0) && view.delta == nil {
			continue
		}

		mask, err := applicableCRLScope(ctx, cert, view.base.list, point)
		if err != nil {
			return 0, err
		}

		if mask == 0 {
			continue
		}

		entry, err := viewCRLEntry(ctx, view, cert)
		if err != nil {
			return 0, err
		}

		if entry != nil {
			if entry.revoked.After(at) {
				return 0, fmt.Errorf("%w: future CRL revocation time", ErrEvidence)
			}

			return 0, ErrRevoked
		}

		if err := useCRLAssertion(ctx, view, cert, issuer, at, mask); err != nil {
			return 0, err
		}
		// Only the newest applicable view for this scope contributes coverage.
		return mask, nil
	}

	return 0, nil
}

func certificateIssuerNames(ctx context.Context, cert *x509.Certificate) ([]crlGeneralName, error) {
	name, err := crlDirectoryName(ctx, cert.RawIssuer)
	if err != nil {
		return nil, err
	}

	names := []crlGeneralName{name}

	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 18}) {
			continue
		}

		value, err := der.Read(extension.Value, 1<<20)
		if err != nil {
			return nil, ErrEvidence
		}

		alternatives, err := parseGeneralNames(ctx, value, false)
		if err != nil {
			return nil, err
		}

		names = append(names, alternatives...)
	}

	return names, nil
}

func compareCRLOrder(a, b *parsedCRL) int {
	if a.this.Before(b.this) {
		return -1
	}

	if a.this.After(b.this) {
		return 1
	}

	if a.number != nil && b.number != nil {
		if order := a.number.Cmp(b.number); order != 0 {
			return order
		}
	}

	return bytes.Compare(a.raw, b.raw)
}

func checkSimultaneousCRLNumbers(group []*authenticatedCRL) error {
	type interval struct {
		number    string
		complete  bool
		delta     bool
		different bool
	}

	byTime := make(map[time.Time]interval)

	for _, auth := range group {
		list := auth.list
		if list.number == nil {
			continue
		}

		item, exists := byTime[list.this]
		if exists && item.number != list.number.String() {
			item.different = true
		}

		item.number = list.number.String()
		item.complete = item.complete || list.base == nil

		item.delta = item.delta || list.base != nil
		if item.complete && item.delta && item.different {
			return fmt.Errorf("%w: simultaneous complete/delta CRL number disagreement", ErrEvidence)
		}

		byTime[list.this] = item
	}

	return nil
}
