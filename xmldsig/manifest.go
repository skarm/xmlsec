package xmldsig

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/tree"
	"github.com/skarm/xmlsec/reference"
)

// ManifestType identifies a Reference to a ds:Manifest.
const ManifestType = Namespace + "Manifest"

// ManifestMode selects whether local Manifest references are recursively validated.
type ManifestMode string

const (
	// ManifestNone means core validation only; a digest of Manifest is not a
	// verification of its references. This is the default.
	ManifestNone ManifestMode = ""
	// ManifestRecursive checks every reference of every directly targeted local
	// ds:Manifest reachable from SignedInfo. It does not scan arbitrary Object
	// descendants, KeyInfo, or external XML for additional Manifests.
	ManifestRecursive ManifestMode = "recursive"
)

// ManifestPolicy sets the Manifest mode and bounded local graph traversal limits.
type ManifestPolicy struct {
	// Mode defaults to ManifestNone; recursive validation is opt-in.
	Mode ManifestMode
	// MaxDepth bounds Manifest nesting; zero selects 8.
	MaxDepth int
	// MaxManifests bounds unique Manifests; zero selects 64.
	// A shared graph node is counted once.
	MaxManifests int
	// MaxReferences bounds direct and nested references; zero selects 256.
	// Each incoming graph edge counts separately.
	MaxReferences int
}

// ManifestResult is an immutable validated local Manifest and its reference results.
type ManifestResult struct {
	target     document.Element
	references []ReferenceResult
}

// Target returns the validated local Manifest element in the verified snapshot.
func (m ManifestResult) Target() document.Element { return m.target }

// References returns an owned slice of immutable validated reference results.
func (m ManifestResult) References() []ReferenceResult {
	return append([]ReferenceResult(nil), m.references...)
}

// ManifestReport records a local Manifest check and its reference diagnostics.
type ManifestReport struct {
	Index      int               `json:"index"`
	ID         string            `json:"id,omitempty"`
	Status     CheckStatus       `json:"status"`
	References []ReferenceReport `json:"references"`
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
	ref      coreReference
	target   *tree.Node
	external bool
	child    *manifestPlan
	owner    *manifestPlan
	index    int
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
}

type manifestGraph struct {
	policy    ManifestPolicy
	direct    []*coreTask
	manifests []*manifestPlan
	tasks     []*coreTask
	byNode    map[*tree.Node]*manifestPlan
	active    map[*tree.Node]bool
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
	verifier := manifestVerifier{ctx: ctx, doc: doc, plan: p, budget: b, result: result, report: report, done: make(map[*manifestPlan]bool)}

	result.manifests = make([]ManifestResult, len(g.manifests))
	for _, m := range g.manifests {
		result.manifests[m.index].target = tree.Wrap(doc, m.node)
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
	if len(b.graph.tasks) >= b.graph.policy.MaxReferences {
		return nil, t.wrap("graph", fmt.Errorf("%w: total Reference count", ErrPolicy))
	}

	b.graph.tasks = append(b.graph.tasks, t)

	var err error

	t.target, t.external, err = taskTarget(b.ctx, b.doc, b.plan, ref)
	if err != nil {
		return nil, t.wrap(nameResolve, err)
	}

	if b.graph.policy.Mode != ManifestRecursive {
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
	m := &manifestPlan{node: t.target, id: id, index: len(g.manifests), height: 1}
	t.child = m
	g.byNode[t.target] = m
	g.active[t.target] = true
	g.manifests = append(g.manifests, m)
	mr := ManifestReport{Index: m.index, ID: id, Status: NotChecked}

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

	g := &manifestGraph{policy: policy, byNode: make(map[*tree.Node]*manifestPlan), active: make(map[*tree.Node]bool)}
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
	rrpt := v.referenceReport(t)

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

	if t.child == nil {
		return nil
	}

	if !rr.CoversElement(tree.Wrap(v.doc, t.child.node)) {
		return v.fail(t, "coverage", fmt.Errorf("%w: Manifest source not fully covered", ErrPolicy))
	}

	return v.checkManifest(t.child)
}

func (v *manifestVerifier) checkManifest(m *manifestPlan) error {
	if v.done[m] {
		return nil
	}

	for _, child := range m.refs {
		if err := v.checkReference(child); err != nil {
			v.report.Manifests[m.index].Status = failureStatus(err)
			return err
		}
	}

	v.done[m] = true
	v.report.Manifests[m.index].Status = Valid

	return nil
}
