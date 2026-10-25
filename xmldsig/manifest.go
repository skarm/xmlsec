package xmldsig

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// ManifestType identifies a Reference to a ds:Manifest.
const ManifestType = Namespace + "Manifest"

// ManifestMode selects whether Manifest references are recursively validated.
type ManifestMode string

const (
	// ManifestNone means core validation only; a digest of Manifest is not a
	// verification of its references. This is the default.
	ManifestNone ManifestMode = ""
	// ManifestRecursive checks every reference of every directly targeted local
	// ds:Manifest reachable from SignedInfo. It does not scan arbitrary Object
	// descendants or KeyInfo for additional Manifests. Typed external roots
	// additionally require ManifestPolicy.AllowExternal and ExternalReferences.
	ManifestRecursive ManifestMode = "recursive"
)

// ManifestPolicy sets the Manifest mode and bounded graph traversal limits.
type ManifestPolicy struct {
	// Mode defaults to ManifestNone; recursive validation is opt-in.
	Mode ManifestMode
	// AllowExternal permits typed external Manifest subresources in
	// recursive mode. ExternalReferences must independently allow every resource.
	// Resolved octets must form a standalone ds:Manifest, with no transform or
	// one C14N transform, unless AllowTransformed is also selected. Fragment
	// interpretation belongs to the resolver.
	// Original bytes are retained under the aggregate external byte limit; nested
	// references are processed only after authenticating the incoming digest.
	AllowExternal bool
	// AllowTransformed permits explicitly typed Manifest references whose
	// approved transforms produce a standalone Manifest document. The exact
	// final digest input is authenticated before parsing or following children.
	// Its IDs and same-document links belong to that derived snapshot, never
	// the original XML. Ordinary original-node coverage claims remain separate.
	AllowTransformed bool
	// MaxDepth bounds Manifest nesting; zero selects 8.
	MaxDepth int
	// MaxManifests bounds unique Manifests; zero selects 64.
	// A shared graph node is counted once.
	MaxManifests int
	// MaxReferences bounds direct and nested references; zero selects 256.
	// Each incoming graph edge counts separately.
	MaxReferences int
}

// ManifestResult is an immutable validated Manifest and its reference results.
type ManifestResult struct {
	target      document.Element
	references  []ReferenceResult
	resource    string
	transformed bool
}

// Target returns the validated Manifest element in its immutable document scope.
func (m ManifestResult) Target() document.Element { return m.target }

// ResourceURI is the containing retrieval URI, or empty for a local source.
// Transformed distinguishes derived snapshots from their original source.
func (m ManifestResult) ResourceURI() string { return m.resource }

// Transformed reports whether Target belongs to an authenticated transform
// result instead of the original signature/resource document.
func (m ManifestResult) Transformed() bool { return m.transformed }

// References returns an owned slice of immutable validated reference results.
func (m ManifestResult) References() []ReferenceResult {
	return append([]ReferenceResult(nil), m.references...)
}

// ManifestReport records a local Manifest check and its reference diagnostics.
type ManifestReport struct {
	Index       int               `json:"index"`
	ID          string            `json:"id,omitempty"`
	ResourceURI string            `json:"resource_uri,omitempty"`
	Transformed bool              `json:"transformed,omitempty"`
	Status      CheckStatus       `json:"status"`
	References  []ReferenceReport `json:"references"`
}

// ManifestReferenceError identifies a nested failure without pretending it is a
// direct SignedInfo reference. Manifest is the report index; ID is diagnostic.
type ManifestReferenceError struct {
	Manifest  int
	ID        string
	Reference *ReferenceError
}

// Error returns the diagnostic error message.
func (e *ManifestReferenceError) Error() string {
	return fmt.Sprintf("Manifest %d (%s): %v", e.Manifest, e.ID, e.Reference)
}

// Unwrap returns the underlying error for errors.Is and errors.As.
func (e *ManifestReferenceError) Unwrap() error { return e.Reference }

// Manifests returns an owned slice of immutable validated Manifest results.
func (r *SignatureResult) Manifests() []ManifestResult {
	if r == nil {
		return nil
	}

	return append([]ManifestResult(nil), r.manifests...)
}

func normalizeManifestPolicy(p ManifestPolicy) (ManifestPolicy, error) {
	if p.Mode != ManifestNone && p.Mode != ManifestRecursive {
		return p, fmt.Errorf("%w: Manifest mode", ErrPolicy)
	}

	if (p.AllowExternal || p.AllowTransformed) && p.Mode != ManifestRecursive {
		return p, fmt.Errorf("%w: Manifest traversal options require recursive mode", ErrPolicy)
	}

	if p.MaxDepth == 0 {
		p.MaxDepth = 8
	}

	if p.MaxManifests == 0 {
		p.MaxManifests = 64
	}

	if p.MaxReferences == 0 {
		p.MaxReferences = 256
	}

	if p.MaxDepth < 1 || p.MaxDepth > 32 || p.MaxManifests < 1 || p.MaxManifests > 256 || p.MaxReferences < 1 || p.MaxReferences > 1024 {
		return p, fmt.Errorf("%w: Manifest limits", ErrPolicy)
	}

	return p, nil
}

type coreTask struct {
	ref         coreReference
	target      *tree.Node
	external    bool
	child       *manifestPlan
	owner       *manifestPlan
	index       int
	scope       *manifestScope
	resourceURI string
}

func (t *coreTask) wrap(stage string, err error) error {
	re := &ReferenceError{t.index, t.ref.uri, stage, err}
	if t.owner != nil {
		return &ManifestReferenceError{t.owner.index, t.owner.id, re}
	}

	return re
}

type manifestPlan struct {
	node   *tree.Node
	id     string
	index  int
	refs   []*coreTask
	height int
	scope  *manifestScope
}

type manifestScope struct {
	doc         *document.Document
	resolver    *reference.SameDocumentResolver
	uri         string
	transformed bool
}

type manifestResourceKey struct {
	uri    string
	output [32]byte
}

type manifestGraph struct {
	policy         ManifestPolicy
	direct         []*coreTask
	manifests      []*manifestPlan
	tasks          []*coreTask
	byNode         map[*tree.Node]*manifestPlan
	active         map[*tree.Node]bool
	externalScopes map[manifestResourceKey]*manifestScope
}

// signingOrder handles dependencies between ALL mutable digest placeholders,
// including non-Manifest container references. Cycles and SignatureValue
// dependencies are rejected before a signer is called.
func (g *manifestGraph) signingOrder(ctx context.Context, p *corePlan) ([]*coreTask, error) {
	traversal := digestDependencyTraversal{ctx: ctx, plan: p, tasks: g.tasks, states: make(map[*coreTask]int)}
	for _, task := range g.tasks {
		if err := traversal.visit(task); err != nil {
			return nil, err
		}
	}

	return traversal.order, nil
}

func (g *manifestGraph) verify(ctx context.Context, doc *document.Document, p *corePlan, b *coreBudget, result *SignatureResult, report *VerificationReport) error {
	verifier := manifestVerifier{ctx: ctx, doc: doc, plan: p, budget: b, result: result, report: report, done: make(map[*manifestPlan]bool), active: make(map[*manifestPlan]bool)}

	result.manifests = make([]ManifestResult, len(g.manifests))
	for _, m := range g.manifests {
		result.manifests[m.index] = ManifestResult{target: tree.Wrap(m.scope.doc, m.node), resource: m.scope.uri, transformed: m.scope.transformed}
	}

	if err := verifyDirect(g, verifier.checkReference, report); err != nil {
		return err
	}

	if g.policy.Mode == ManifestRecursive {
		report.ManifestValidation = Valid
	}

	return nil
}

func verifyDirect(g *manifestGraph, check func(*coreTask) error, report *VerificationReport) error {
	for _, t := range g.direct {
		if err := check(t); err != nil {
			if g.policy.Mode == ManifestRecursive {
				report.ManifestValidation = failureStatus(err)
			}

			return err
		}
	}

	return nil
}

// manifestGraphBuilder keeps the recursive traversal's inputs and partial graph.
// Registration precedes child parsing so reports and cycle checks retain order.
type manifestGraphBuilder struct {
	ctx      context.Context
	doc      *document.Document
	plan     *corePlan
	graph    *manifestGraph
	template bool
	report   *VerificationReport
}

func (b *manifestGraphBuilder) buildReference(ref coreReference, owner *manifestPlan, index, depth int) (*coreTask, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}

	t := &coreTask{ref: ref, owner: owner, index: index}
	if owner != nil {
		t.scope = owner.scope
	} else {
		t.scope = &manifestScope{doc: b.doc, resolver: b.plan.resolver}
	}

	if len(b.graph.tasks) >= b.graph.policy.MaxReferences {
		return nil, t.wrap("graph", fmt.Errorf("%w: total Reference count", ErrPolicy))
	}

	b.graph.tasks = append(b.graph.tasks, t)

	var err error

	t.target, t.external, t.resourceURI, err = taskTarget(b.ctx, t.scope, b.plan, ref)
	if err != nil {
		return nil, t.wrap(nameResolve, err)
	}

	if b.graph.policy.Mode != ManifestRecursive {
		return t, nil
	}

	if t.external && ref.typeURI == ManifestType {
		if !b.graph.policy.AllowExternal {
			return nil, t.wrap("graph", fmt.Errorf("%w: external Manifest traversal is not enabled", ErrPolicy))
		}

		if !externalManifestProvenance(ref.transforms) && !b.graph.policy.AllowTransformed {
			return nil, t.wrap("graph", fmt.Errorf("%w: external Manifest edge must preserve the complete XML source", ErrPolicy))
		}

		return t, nil // discover contents only after the incoming digest is authenticated
	}

	if transformedManifestEdge(t) {
		if !b.graph.policy.AllowTransformed {
			return nil, t.wrap("graph", fmt.Errorf("%w: transformed Manifest traversal is not enabled", ErrPolicy))
		}

		return t, nil
	}

	traverse, err := manifestEdgeTarget(t)
	if err != nil {
		return nil, t.wrap("graph", err)
	}

	if traverse {
		if err := b.attachManifest(t, depth); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// manifestEdgeTarget validates the edge before any depth or child checks.
func manifestEdgeTarget(t *coreTask) (bool, error) {
	if t.external {
		if t.ref.typeURI == ManifestType {
			return false, fmt.Errorf("%w: external Manifest traversal", ErrAlgorithm)
		}

		return false, nil
	}

	isManifest := isDS(t.target, "Manifest")
	if t.ref.typeURI == ManifestType && !isManifest {
		return false, fmt.Errorf("%w: Manifest Type does not target ds:Manifest", ErrStructure)
	}

	if !isManifest {
		return false, nil
	}
	// Do not validate untransformed source XML while claiming that arbitrary
	// transformed octets authenticated it. Only complete provenance is allowed.
	if !manifestProvenance(t.ref.transforms) {
		return false, fmt.Errorf("%w: Manifest edge loses original-node provenance", ErrPolicy)
	}

	return true, nil
}

func manifestProvenance(ts []reference.Transform) bool {
	canonical := false
	for _, tr := range ts {
		if canonical {
			return false
		}

		if tr.Algorithm == EnvelopedSignature {
			continue
		}

		if !canonicalAlgorithm(tr.Algorithm) {
			return false
		}

		canonical = true
	}

	return true // no final C14N means implicit C14N 1.0
}

func externalManifestProvenance(ts []reference.Transform) bool {
	return len(ts) == 0 || (len(ts) == 1 && canonicalAlgorithm(ts[0].Algorithm))
}

func transformedManifestEdge(t *coreTask) bool {
	if t.ref.typeURI != ManifestType {
		return false
	}

	if t.external {
		return !externalManifestProvenance(t.ref.transforms)
	}

	return !isDS(t.target, "Manifest") || !manifestProvenance(t.ref.transforms)
}

// Generation validates complete discovered graphs before asking a private signer
// to authorize the newly filled SignedInfo. The check uses its own node/octet
// processing budget and the same bounded, immutable resource evidence cache.
func validateGeneratedManifests(ctx context.Context, doc *document.Document, p *corePlan) error {
	if !p.graph.policy.AllowExternal && !p.graph.policy.AllowTransformed {
		return nil
	}

	needed := false

	for _, task := range p.graph.tasks {
		if (task.external && task.ref.typeURI == ManifestType) || transformedManifestEdge(task) {
			needed = true
			break
		}
	}

	if !needed {
		return nil
	}

	check := *p
	check.refs = make([]coreReference, len(p.graph.direct))

	report := &VerificationReport{References: make([]ReferenceReport, len(check.refs))}
	for i, task := range p.graph.direct {
		check.refs[i] = task.ref
		report.References[i] = ReferenceReport{Index: i, URI: task.ref.uri, Status: NotChecked}
	}

	var err error

	check.graph, err = prepareManifestGraph(ctx, doc, &check, p.graph.policy, false, report)
	if err != nil {
		return err
	}

	return check.graph.verify(ctx, doc, &check, newCoreBudget(&check), &SignatureResult{doc: doc}, report)
}

func (b *manifestGraphBuilder) attachManifest(t *coreTask, depth int) error {
	g := b.graph
	if depth > g.policy.MaxDepth {
		return t.wrap("graph", fmt.Errorf("%w: Manifest depth", ErrPolicy))
	}

	if g.active[t.target] {
		return t.wrap("graph", fmt.Errorf("%w: cyclic Manifest graph", ErrReference))
	}

	if m, ok := g.byNode[t.target]; ok {
		if depth+m.height-1 > g.policy.MaxDepth {
			return t.wrap("graph", fmt.Errorf("%w: shared Manifest depth", ErrPolicy))
		}

		t.child = m

		return nil
	}

	children, err := b.registerManifest(t)
	if err != nil {
		return t.wrap("graph", err)
	}

	if err := b.buildManifestReferences(t.child, children, depth); err != nil {
		return err
	}

	g.active[t.target] = false

	return nil
}

func (b *manifestGraphBuilder) registerManifest(t *coreTask) ([]*tree.Node, error) {
	g := b.graph
	if len(g.manifests) >= g.policy.MaxManifests {
		return nil, fmt.Errorf("%w: Manifest count", ErrPolicy)
	}

	children, err := structure(t.target, "Manifest", "Id")
	if err != nil {
		return nil, err
	}

	if len(children) == 0 || len(children) > b.plan.policy.MaxReferences {
		return nil, fmt.Errorf("%w: Manifest Reference count", ErrPolicy)
	}

	id, _ := getAttr(t.target, document.Name{Local: "Id"})
	m := &manifestPlan{node: t.target, id: id, index: len(g.manifests), height: 1, scope: t.scope}
	t.child = m
	g.byNode[t.target] = m
	g.active[t.target] = true
	g.manifests = append(g.manifests, m)
	mr := ManifestReport{Index: m.index, ID: id, ResourceURI: m.scope.uri, Transformed: m.scope.transformed, Status: NotChecked}

	for i, n := range children {
		uri, _ := getAttr(n, document.Name{Local: "URI"})
		mr.References = append(mr.References, ReferenceReport{Index: i, URI: uri, Status: NotChecked})
	}

	b.report.Manifests = append(b.report.Manifests, mr)

	return children, nil
}

func (b *manifestGraphBuilder) buildManifestReferences(m *manifestPlan, children []*tree.Node, depth int) error {
	for i, n := range children {
		r, err := parseCoreReference(b.ctx, n, b.plan.policy, b.plan.processing, b.template)
		if err != nil {
			return (&coreTask{ref: r, owner: m, index: i}).wrap("structure", err)
		}

		if m.scope.uri != "" {
			if err := reference.PrepareTransforms(b.ctx, r.transforms, b.plan.processing); err != nil {
				return (&coreTask{ref: r, owner: m, index: i}).wrap("preflight", processingError(err))
			}
		}

		child, err := b.buildReference(r, m, i, depth+1)
		if err != nil {
			return err
		}

		m.refs = append(m.refs, child)
		if child.child != nil && child.child.height+1 > m.height {
			m.height = child.child.height + 1
		}
	}

	return nil
}

func prepareManifestGraph(ctx context.Context, doc *document.Document, p *corePlan, policy ManifestPolicy, template bool, report *VerificationReport) (*manifestGraph, error) {
	policy, err := normalizeManifestPolicy(policy)
	if err != nil {
		return nil, err
	}

	g := &manifestGraph{policy: policy, byNode: make(map[*tree.Node]*manifestPlan), active: make(map[*tree.Node]bool), externalScopes: make(map[manifestResourceKey]*manifestScope)}
	if p.external != nil {
		p.external.captureManifests = policy.AllowExternal
		p.external.captureTransformed = policy.AllowTransformed
	}

	builder := manifestGraphBuilder{ctx: ctx, doc: doc, plan: p, graph: g, template: template, report: report}

	for i, ref := range p.refs {
		t, err := builder.buildReference(ref, nil, i, 1)
		if err != nil {
			return nil, err
		}

		g.direct = append(g.direct, t)
	}

	return g, nil
}

type digestDependencyTraversal struct {
	ctx    context.Context
	plan   *corePlan
	tasks  []*coreTask
	states map[*coreTask]int
	order  []*coreTask
}

func (d *digestDependencyTraversal) visit(t *coreTask) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}

	if d.states[t] == 1 {
		return t.wrap("dependency", fmt.Errorf("%w: cyclic digest dependency", ErrPolicy))
	}

	if d.states[t] == 2 {
		return nil
	}

	d.states[t] = 1
	if !t.external {
		if err := d.visitDependencies(t); err != nil {
			return err
		}
	}

	d.states[t] = 2
	d.order = append(d.order, t)

	return nil
}

func (d *digestDependencyTraversal) visitDependencies(t *coreTask) error {
	excludes := excludesContaining(t.ref.transforms)
	if within(d.plan.sv, t.target) && !excludes {
		return t.wrap("dependency", fmt.Errorf("%w: reference depends on SignatureValue", ErrPolicy))
	}

	for _, other := range d.tasks {
		if !within(other.ref.digestNode, t.target) {
			continue
		}

		if excludes && within(other.ref.digestNode, d.plan.sig) {
			continue
		}

		if err := d.visit(other); err != nil {
			return err
		}
	}

	return nil
}

func excludesContaining(ts []reference.Transform) bool {
	return len(ts) > 0 && ts[0].Algorithm == EnvelopedSignature
}

type manifestVerifier struct {
	ctx    context.Context
	doc    *document.Document
	plan   *corePlan
	budget *coreBudget
	result *SignatureResult
	report *VerificationReport
	done   map[*manifestPlan]bool
	active map[*manifestPlan]bool
}

func (v *manifestVerifier) referenceReport(t *coreTask) *ReferenceReport {
	if t.owner == nil {
		return &v.report.References[t.index]
	}

	return &v.report.Manifests[t.owner.index].References[t.index]
}

func (v *manifestVerifier) fail(t *coreTask, stage string, err error) error {
	rrpt := v.referenceReport(t)
	rrpt.Status = failureStatus(err)
	rrpt.Stage = stage

	rrpt.Error = err.Error()
	if t.owner != nil {
		v.report.Manifests[t.owner.index].Status = rrpt.Status
	}

	return t.wrap(stage, err)
}

func (v *manifestVerifier) checkReference(t *coreTask) error {
	return v.checkReferenceAt(t, 1)
}

func (v *manifestVerifier) checkReferenceAt(t *coreTask, depth int) error {
	rrpt := v.referenceReport(t)

	rrpt.ResourceURI = t.resourceURI
	if t.external && t.ref.typeURI == ManifestType && v.plan.graph.policy.AllowExternal && !transformedManifestEdge(t) {
		if scope := v.plan.graph.externalScopes[manifestResourceKey{uri: t.resourceURI}]; scope != nil && v.active[v.plan.graph.byNode[tree.Root(scope.doc)]] {
			return v.fail(t, "graph", fmt.Errorf("%w: cyclic external Manifest graph", ErrReference))
		}
	}

	processed, rr, err := processCoreTask(v.ctx, v.doc, v.plan, v.budget, t)
	if err != nil {
		return v.fail(t, "process", err)
	}

	rrpt.Steps = processed.Steps()

	if subtle.ConstantTimeCompare(rr.digest, t.ref.digest) != 1 {
		return v.fail(t, "digest", ErrDigest)
	}

	rrpt.Status = Valid

	if t.owner == nil {
		v.result.references = append(v.result.references, rr)
	} else {
		v.result.manifests[t.owner.index].references = append(v.result.manifests[t.owner.index].references, rr)
	}

	if (t.external && t.ref.typeURI == ManifestType && v.plan.graph.policy.AllowExternal) || (v.plan.graph.policy.Mode == ManifestRecursive && v.plan.graph.policy.AllowTransformed && transformedManifestEdge(t)) {
		if err := v.attachExternalManifest(t, rr, depth); err != nil {
			// The incoming reference digest has passed. Discovery/content errors
			// must not relabel that authenticated byte reference as a digest failure.
			if _, ok := errors.AsType[*ManifestReferenceError](err); ok {
				return err
			}

			return &ManifestReferenceError{Manifest: -1, ID: t.ref.uri, Reference: &ReferenceError{Index: t.index, URI: t.ref.uri, Stage: "manifest", Err: err}}
		}
	}

	if t.child == nil {
		return nil
	}

	if !t.external && !transformedManifestEdge(t) && !rr.CoversElement(tree.Wrap(t.child.scope.doc, t.child.node)) {
		return v.fail(t, "coverage", fmt.Errorf("%w: Manifest source not fully covered", ErrPolicy))
	}

	return v.checkManifest(t.child, depth)
}

func (v *manifestVerifier) checkManifest(m *manifestPlan, depth int) error {
	if depth+m.height-1 > v.plan.graph.policy.MaxDepth {
		return fmt.Errorf("%w: Manifest depth", ErrPolicy)
	}

	if v.active[m] {
		return fmt.Errorf("%w: cyclic Manifest graph", ErrReference)
	}

	if v.done[m] {
		return nil
	}

	v.active[m] = true
	defer delete(v.active, m)

	for _, child := range m.refs {
		if err := v.checkReferenceAt(child, depth+1); err != nil {
			v.report.Manifests[m.index].Status = failureStatus(err)
			return err
		}

		if child.child != nil && child.child.height+1 > m.height {
			m.height = child.child.height + 1
		}
	}

	v.done[m] = true
	v.report.Manifests[m.index].Status = Valid

	return nil
}

// attachExternalManifest consumes authenticated original resource bytes or the
// captured final transform output. It never reruns transforms to discover XML.
func (v *manifestVerifier) attachExternalManifest(t *coreTask, rr ReferenceResult, depth int) error {
	g := v.plan.graph
	if depth > g.policy.MaxDepth {
		return fmt.Errorf("%w: Manifest depth", ErrPolicy)
	}

	key := manifestResourceKey{uri: t.resourceURI}

	var data []byte

	derived := transformedManifestEdge(t)
	if derived {
		data = rr.manifestInput

		key.output = sha256.Sum256(data)
		if !t.external {
			key.uri = t.scope.uri
		}
	} else if rr.external != nil {
		data = rr.external.rawManifest
	}

	scope := g.externalScopes[key]
	if scope == nil {
		if len(g.manifests) >= g.policy.MaxManifests {
			return fmt.Errorf("%w: Manifest count", ErrPolicy)
		}

		if data == nil {
			return fmt.Errorf("%w: authenticated Manifest bytes unavailable", ErrReference)
		}

		limits := document.DefaultLimits()
		if derived {
			limits.MaxBytes = min(limits.MaxBytes, v.plan.policy.MaxCanonicalBytes)
		} else {
			limits.MaxBytes = min(limits.MaxBytes, v.plan.external.limits.MaxResourceBytes)
		}

		limits.MaxNodes = min(limits.MaxNodes, v.budget.visits/2)

		limits.MaxNodeSetNodes = min(limits.MaxNodeSetNodes, v.budget.visits/2)
		if v.budget.visits < 2 {
			return ErrPolicy
		}

		doc, err := document.Parse(v.ctx, data, limits)
		if err != nil {
			if errors.Is(err, document.ErrLimit) {
				return fmt.Errorf("%w: external Manifest XML: %w", ErrPolicy, err)
			}

			return fmt.Errorf("%w: external Manifest XML: %w", ErrReference, err)
		}

		if !isDS(tree.Root(doc), "Manifest") {
			return fmt.Errorf("%w: external root must be ds:Manifest", ErrStructure)
		}

		set, err := doc.AllNodes(v.ctx)
		if err != nil {
			return fmt.Errorf("%w: Manifest node budget: %w", ErrPolicy, err)
		}

		v.budget.visits -= 2 * set.Len()

		resolver, err := reference.NewSameDocumentResolverWithRules(v.ctx, doc, v.plan.processing.IDRules)
		if err != nil {
			return fmt.Errorf("%w: Manifest ID scope: %w", ErrReference, err)
		}

		scope = &manifestScope{doc: doc, resolver: resolver, uri: key.uri, transformed: derived}
		g.externalScopes[key] = scope
	}
	// The edge belongs to its parent's scope; its attached node and descendants
	// belong to the authenticated original or derived document.
	edge := *t
	edge.scope = scope
	edge.target = tree.Root(scope.doc)

	builder := manifestGraphBuilder{ctx: v.ctx, doc: v.doc, plan: v.plan, graph: g, report: v.report}
	if err := builder.attachManifest(&edge, depth); err != nil {
		return err
	}

	t.child = edge.child

	for len(v.result.manifests) < len(g.manifests) {
		m := g.manifests[len(v.result.manifests)]
		v.result.manifests = append(v.result.manifests, ManifestResult{target: tree.Wrap(m.scope.doc, m.node), resource: m.scope.uri, transformed: m.scope.transformed})
	}

	return nil
}
