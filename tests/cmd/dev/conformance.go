package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	conformanceFull     = "full"
	conformancePartial  = "partial"
	conformancePending  = "pending"
	conformanceCovered  = "covered"
	conformanceComplete = "complete"
	normNotApplicable   = "not-applicable"
	normImplemented     = "implemented"
	normPublisher       = "publisher"
	normXPath20         = "XP20"
	normXPath30         = "XP30"
	normXPath31         = "XP31"
)

type conformanceRegister struct {
	SchemaVersion int                    `json:"schema_version"`
	ReviewedOn    string                 `json:"reviewed_on"`
	Completeness  string                 `json:"completeness"`
	Scope         string                 `json:"scope"`
	Stage         string                 `json:"stage"`
	Documents     []standardDocument     `json:"documents"`
	Profiles      []conformanceProfile   `json:"profiles"`
	Requirements  []scopeRequirement     `json:"requirements"`
	Normative     []normativeRequirement `json:"normative_requirements"`
	Residual      []residualEvidence     `json:"residual_evidence,omitempty"`
}

type residualEvidence struct {
	Suite       string                     `json:"suite"`
	File        string                     `json:"file"`
	Name        string                     `json:"name"`
	Disposition string                     `json:"disposition"`
	Reason      string                     `json:"reason"`
	Checks      []conformanceTest          `json:"checks"`
	Failures    []residualFailureCondition `json:"failures,omitempty"`
}

type residualFailureCondition struct {
	Profile    string   `json:"profile"`
	Kind       string   `json:"kind"`
	ErrorCodes []string `json:"error_codes"`
	Cause      string   `json:"cause"`
	Signature  string   `json:"signature,omitempty"`
}

type standardDocument struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Edition string `json:"edition"`
	Source  string `json:"source"`
	Errata  struct {
		Sources    []string             `json:"sources"`
		Review     string               `json:"review"`
		ReviewedOn string               `json:"reviewed_on"`
		Items      []standardCorrection `json:"items"`
		Notes      string               `json:"notes"`
	} `json:"errata"`
}

type standardCorrection struct {
	ID          string `json:"id"`
	Disposition string `json:"disposition"`
	Clause      string `json:"clause"`
	Reason      string `json:"reason"`
}

type conformanceProfile struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Role        string          `json:"role"`
	Modes       []string        `json:"modes"`
	Claim       string          `json:"claim"`
	Inventory   string          `json:"inventory"`
	Documents   []string        `json:"documents"`
	ScopeIDs    []string        `json:"scope_ids"`
	PackageDocs []string        `json:"package_docs"`
	Gap         string          `json:"gap"`
	Closure     string          `json:"closure"`
	Matrix      []profileMatrix `json:"matrix"`
}

// A matrix row accounts for a pinned document within one selected role. It
// names both assessed obligations and the exact remaining inventory boundary.
type profileMatrix struct {
	Document     string   `json:"document"`
	Modes        []string `json:"modes"`
	Requirements []string `json:"requirements"`
	Unmapped     []string `json:"unmapped_clauses"`
	Reason       string   `json:"reason"`
	Closure      string   `json:"closure"`
}

// Scope entries retain the original capability IDs. They are deliberately not
// counted as individual normative obligations.
type scopeRequirement struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Source         *string  `json:"source"`
	Status         string   `json:"status"`
	Tests          []string `json:"tests"`
	Implementation []string `json:"implementation"`
	Standards      []string `json:"standards"`
	Errata         string   `json:"errata"`
	Notes          string   `json:"notes"`
	Limitations    string   `json:"limitations"`
}

type conformanceTest struct {
	File string `json:"file"`
	Name string `json:"name"`
	Case string `json:"case,omitempty"`
}

// normativeEvidence records executable witnesses for one finite obligation.
// A publisher assertion and a processor agreement remain different oracles.
type normativeEvidence struct {
	Obligation string           `json:"obligation"`
	Positive   []normativeProof `json:"positive"`
	Negative   []normativeProof `json:"negative"`
}

type normativeProof struct {
	Check    conformanceTest `json:"check,omitzero"`
	Oracle   string          `json:"oracle,omitempty"`
	Source   string          `json:"source,omitempty"`
	Expected *string         `json:"expected,omitempty"`
	Basis    string          `json:"basis,omitempty"`
	Catalog  *catalogProof   `json:"catalog,omitempty"`
}

type catalogProof struct {
	Suite      string   `json:"suite"`
	File       string   `json:"file"`
	Name       string   `json:"name,omitempty"`
	Names      []string `json:"names,omitempty"`
	Version    string   `json:"version"`
	XSDVersion string   `json:"xsd_version"`
}

// Bundles store exact publisher identities once per file/edition. Expansion
// preserves separate full-assertion executions, never a name-pattern selection.
func expandNormativeProof(id string, proof normativeProof) []normativeProof {
	if proof.Catalog == nil || len(proof.Catalog.Names) == 0 {
		return []normativeProof{proof}
	}

	proofs := make([]normativeProof, 0, len(proof.Catalog.Names))
	for _, name := range proof.Catalog.Names {
		item := proof
		catalog := *proof.Catalog
		catalog.Name, catalog.Names = name, nil
		item.Catalog = &catalog
		item.Oracle = normPublisher
		item.Check = conformanceTest{File: "tests/cmd/dev/main_test.go", Name: "TestLanguageNormativeEvidence", Case: id + "/" + name}
		proofs = append(proofs, item)
	}

	return proofs
}

func catalogProofIdentity(p catalogProof) string {
	return strings.Join([]string{p.Suite, p.File, p.Name, p.Version, p.XSDVersion}, "\x00")
}

type normativeRequirement struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Norm      struct {
		Document string   `json:"document"`
		Clause   string   `json:"clause"`
		Level    string   `json:"level"`
		Source   string   `json:"source"`
		Errata   []string `json:"errata"`
	} `json:"norm"`
	Applies struct {
		Profile string `json:"profile"`
		Role    string `json:"role"`
		Mode    string `json:"mode"`
		Status  string `json:"status"`
		Reason  string `json:"reason"`
	} `json:"applies"`
	Implementation struct {
		Status string   `json:"status"`
		APIs   []string `json:"apis"`
		Code   []string `json:"code"`
	} `json:"implementation"`
	Tests struct {
		Status   string            `json:"status"`
		Reason   string            `json:"reason"`
		Positive []conformanceTest `json:"positive"`
		Negative []conformanceTest `json:"negative"`
	} `json:"tests"`
	Interop struct {
		Status   string            `json:"status"`
		Tests    []conformanceTest `json:"tests"`
		Fixtures []string          `json:"fixtures"`
		Reason   string            `json:"reason"`
	} `json:"interop"`
	Policy struct {
		Default       policyPermission `json:"default"`
		Compatibility policyPermission `json:"compatibility"`
	} `json:"policy"`
	Gap                 string              `json:"gap"`
	Closure             string              `json:"closure"`
	Evidence            []normativeEvidence `json:"evidence,omitempty"`
	EvidenceFrom        []string            `json:"evidence_from,omitempty"`
	EvidenceComposition string              `json:"evidence_composition,omitempty"`
}

type policyPermission struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type conformanceCheck struct {
	root            string
	problems        []error
	documents       map[string]standardDocument
	profiles        map[string]conformanceProfile
	scopes          map[string]bool
	symbols         map[string]map[string]bool
	evidenceChecked map[string]bool
}

func checkConformanceRegister(root string, data []byte) (int, []error, error) {
	var register conformanceRegister

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&register); err != nil {
		return 0, nil, fmt.Errorf("conformance register: %w", err)
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		return 0, nil, errors.New("conformance register has trailing JSON")
	}

	if register.SchemaVersion != 4 || len(register.Requirements) == 0 || len(register.Normative) == 0 || len(register.Profiles) == 0 || len(register.Documents) == 0 {
		return 0, nil, errors.New("conformance register requires schema 4 and nonempty scope, normative, profile and document inventories")
	}

	c := &conformanceCheck{root: root, documents: make(map[string]standardDocument), profiles: make(map[string]conformanceProfile), scopes: make(map[string]bool), symbols: make(map[string]map[string]bool)}
	c.text("register", register.Completeness, register.Scope, register.Stage)

	if _, err := time.Parse(time.DateOnly, register.ReviewedOn); err != nil {
		c.problem("register", "reviewed_on must be an ISO date")
	}

	for _, entry := range register.Requirements {
		if entry.ID == "" || c.scopes[entry.ID] {
			c.problem(entry.ID, "empty/duplicate capability ID")
		}

		c.scopes[entry.ID] = true
		c.text(entry.ID, entry.Title, entry.Status)

		for _, name := range entry.Tests {
			c.path(entry.ID, name)
		}
	}

	for _, document := range register.Documents {
		c.document(document)
	}

	for _, profile := range register.Profiles {
		c.profile(profile)
	}

	ids := make(map[string]normativeRequirement)
	for _, requirement := range register.Normative {
		if _, exists := ids[requirement.ID]; requirement.ID == "" || exists || c.scopes[requirement.ID] {
			c.problem(requirement.ID, "empty/duplicate normative ID")
		}

		ids[requirement.ID] = requirement
		c.requirement(requirement)
	}

	for _, profile := range register.Profiles {
		c.matrix(profile, ids)

		if !slices.ContainsFunc(register.Normative, func(r normativeRequirement) bool { return r.Applies.Profile == profile.ID }) {
			c.problem(profile.ID, "profile has no normative entries")
		}
	}

	for _, requirement := range register.Normative {
		c.normativeEvidence(requirement, ids, make(map[string]bool))
	}

	residuals := make(map[string]bool)

	for _, residual := range register.Residual {
		id := residual.Suite + "/" + residual.File + "/" + residual.Name
		if residuals[id] {
			c.problem(id, "duplicate residual evidence")
		}

		residuals[id] = true
		c.choice(id, residual.Suite, "qt3", "xslt30")
		c.choice(id, residual.Disposition, "fixed", "resource-limit", "fixture", "optional-feature", "permitted-outcome")
		c.text(id, residual.File, residual.Name, residual.Reason)

		if len(residual.Checks) == 0 {
			c.problem(id, "residual cause requires executable checks")
		}

		for _, check := range residual.Checks {
			c.test(id, check)
			c.text(id, check.Case)
		}

		c.residualConditions(id, residual)
	}

	return len(register.Requirements), c.problems, nil
}

func (c *conformanceCheck) residualConditions(id string, residual residualEvidence) {
	if residual.Disposition == "fixed" && len(residual.Failures) != 0 || residual.Disposition != "fixed" && len(residual.Failures) == 0 {
		c.problem(id, "retained failures require exact profile and typed cause conditions; fixed cases require none")
	}

	seen := make(map[string]bool)
	for _, failure := range residual.Failures {
		if seen[failure.Profile] || !slices.Contains(languageProofProfileKeys(), failure.Profile) {
			c.problem(id, "unknown or duplicate residual failure profile")
		}

		seen[failure.Profile] = true
		c.choice(id, failure.Kind, "assertion", suiteResourceLimit, suiteHarnessFailure)
		c.choice(id, failure.Cause, "assertion-mismatch", "execution-error", "assertion-error", "unsupported-warning", "harness-error", "resource-bound")

		if len(failure.ErrorCodes) == 0 || failure.Kind == suiteResourceLimit && failure.Cause != "resource-bound" {
			c.problem(id, "residual condition requires explicit error-code alternatives and a matching typed resource cause")
		}

		if failure.Kind != suiteResourceLimit && failure.Signature == "" || failure.Kind == suiteResourceLimit && failure.Signature != "" {
			c.problem(id, "non-resource failures require a stable diagnostic signature; timing-dependent resource text must be excluded")
		}

		codes := make(map[string]bool)
		for _, code := range failure.ErrorCodes {
			if codes[code] {
				c.problem(id, "duplicate residual error-code alternative")
			}

			codes[code] = true
		}
	}
}

func languageVerificationDocument(id string) bool {
	return slices.Contains([]string{normXPath20, normXPath30, normXPath31, "FO20", "FO30", "FO31", "XSLT20", "XSLT30", "SER20", "SER30", "SER31"}, id)
}

func (c *conformanceCheck) normativeEvidence(r normativeRequirement, ids map[string]normativeRequirement, visiting map[string]bool) {
	if visiting[r.ID] {
		c.problem(r.ID, "cyclic normative evidence inheritance")
		return
	}

	if c.evidenceChecked[r.ID] {
		return
	}

	if c.evidenceChecked == nil {
		c.evidenceChecked = make(map[string]bool)
	}

	visiting[r.ID] = true
	defer func() { delete(visiting, r.ID); c.evidenceChecked[r.ID] = true }()

	if languageVerificationDocument(r.Norm.Document) && r.Applies.Status != normNotApplicable && (r.Tests.Status != conformanceCovered || r.Interop.Status != conformanceCovered || len(r.Evidence)+len(r.EvidenceFrom) == 0) {
		c.problem(r.ID, "language verification requires closed case-level local and independent evidence")
	}

	if r.Applies.Status == normNotApplicable && len(r.Evidence)+len(r.EvidenceFrom) != 0 {
		c.problem(r.ID, "non-applicable requirement cannot claim executable witnesses")
	}

	c.evidenceInheritance(r, ids, visiting)
	c.caseEvidence(r)
}

func (c *conformanceCheck) evidenceInheritance(r normativeRequirement, ids map[string]normativeRequirement, visiting map[string]bool) {
	c.unique(r.ID, r.EvidenceFrom)

	children := normativeEvidenceChildren(r, ids)
	if len(r.EvidenceFrom) > 0 || languageVerificationDocument(r.Norm.Document) && r.Applies.Status != normNotApplicable && len(children) > 0 {
		for _, id := range children {
			if !slices.Contains(r.EvidenceFrom, id) {
				c.problem(r.ID, "inheritance omits structural child: "+id)
			}
		}

		structural := len(children) > 0
		for _, id := range children {
			structural = structural && slices.Contains(r.EvidenceFrom, id)
		}

		for _, id := range r.EvidenceFrom {
			structural = structural && slices.Contains(children, id)
		}

		if !structural && (len(r.Evidence) == 0 || strings.TrimSpace(r.EvidenceComposition) == "") {
			c.problem(r.ID, "inheritance requires every structural child or directly tested composition with a normative basis")
		}
	}

	for _, id := range r.EvidenceFrom {
		child, ok := ids[id]
		if !ok || child.Applies.Status == normNotApplicable || child.Applies.Profile != r.Applies.Profile || child.Applies.Role != r.Applies.Role {
			c.problem(r.ID, "missing or mismatched inherited evidence: "+id)
			continue
		}

		if len(child.Evidence)+len(child.EvidenceFrom) == 0 || child.Tests.Status != conformanceCovered || child.Interop.Status != conformanceCovered {
			c.problem(r.ID, "inherited evidence is not closed: "+id)
		}

		c.normativeEvidence(child, ids, visiting)
	}
}

func (c *conformanceCheck) caseEvidence(r normativeRequirement) {
	seen := make(map[string]bool)

	for _, evidence := range r.Evidence {
		c.text(r.ID, evidence.Obligation)

		if seen[evidence.Obligation] || len(evidence.Positive) == 0 || len(evidence.Negative) == 0 {
			c.problem(r.ID, "evidence needs distinct obligations and positive/negative witnesses")
		}

		seen[evidence.Obligation] = true
		for _, proofs := range [][]normativeProof{evidence.Positive, evidence.Negative} {
			for _, proof := range proofs {
				c.evidenceProof(r, proof)
			}
		}
	}
}

func (c *conformanceCheck) evidenceProof(r normativeRequirement, proof normativeProof) {
	if proof.Catalog != nil && len(proof.Catalog.Names) > 0 {
		c.unique(r.ID, proof.Catalog.Names)

		if proof.Catalog.Name != "" || proof.Check != (conformanceTest{}) || proof.Oracle != "" && proof.Oracle != normPublisher {
			c.problem(r.ID, "ambiguous publisher proof bundle")
		}
	}

	for _, item := range expandNormativeProof(r.ID, proof) {
		c.proof(r, item)
	}
}

func normativeAggregate(id string) bool {
	return slices.Contains([]string{
		"N-XSLT20-BASIC", "N-XSLT30-BASIC", "N-XSLT20-COMPILATION", "N-XSLT30-COMPILATION",
		"N-XP20-CONTEXT", "N-XP30-CONTEXT", "N-XP31-CONTEXT", "N-FO20-FUNCTION-FAMILIES", "N-FO30-FUNCTION-FAMILIES", "N-FO31-FUNCTION-FAMILIES",
		"N-XPATH30-SERIALIZATION", "N-XPATH31-SERIALIZATION", "N-XSLT20-SERIALIZATION", "N-XSLT30-SERIALIZATION",
		"N-XP20-CLAUSE-F", "N-XP20-CLAUSE-G", "N-XP30-CLAUSE-F", "N-XP30-CLAUSE-G", "N-XP31-CLAUSE-4", "N-XP31-CLAUSE-F",
	}, id)
}

// Structural inheritance means the complete recorded subtree. Other relations
// require their own executable composition witnesses and a published basis.
func normativeEvidenceChildren(r normativeRequirement, ids map[string]normativeRequirement) []string {
	var children []string

	aggregate := normativeAggregate(r.ID)
	profileAggregate := slices.Contains([]string{"N-XP20-CLAUSE-F", "N-XP30-CLAUSE-F", "N-XP31-CLAUSE-4"}, r.ID)

	canonical := strings.Contains(r.ID, "-CLAUSE-") || strings.Contains(r.ID, "-CONTRACT-")
	for id, child := range ids {
		if id == r.ID || !profileAggregate && child.Norm.Document != r.Norm.Document || child.Applies.Profile != r.Applies.Profile || child.Applies.Status == normNotApplicable || normativeAggregate(id) {
			continue
		}

		if aggregate {
			children = append(children, id)
		} else if canonical && (strings.Contains(id, "-CLAUSE-") || strings.Contains(id, "-CONTRACT-")) && strings.HasPrefix(child.Norm.Clause, r.Norm.Clause+".") {
			immediate := true

			for _, between := range ids {
				if between.Applies.Profile == r.Applies.Profile && between.Norm.Document == r.Norm.Document && between.Applies.Status != normNotApplicable &&
					(strings.Contains(between.ID, "-CLAUSE-") || strings.Contains(between.ID, "-CONTRACT-")) &&
					strings.HasPrefix(between.Norm.Clause, r.Norm.Clause+".") && strings.HasPrefix(child.Norm.Clause, between.Norm.Clause+".") {
					immediate = false
					break
				}
			}

			if immediate {
				children = append(children, id)
			}
		}
	}

	slices.Sort(children)

	return children
}

func (c *conformanceCheck) proof(r normativeRequirement, proof normativeProof) {
	c.test(r.ID, proof.Check)
	c.text(r.ID, proof.Check.Case)

	if proof.Source != "" || proof.Oracle != normPublisher {
		c.webURL(r.ID, proof.Source)
	}

	c.choice(r.ID, proof.Oracle, normPublisher, "saxon-9.4", "saxon-12.10", "libxml2", "libxslt", "published-schema", "published-vector", "published-inventory")

	if proof.Oracle == "published-vector" || proof.Oracle == "published-inventory" {
		c.text(r.ID, proof.Basis)

		if proof.Expected == nil {
			c.problem(r.ID, "missing required description: published expected value")
		}
	}

	if proof.Oracle == "published-inventory" && (!slices.Contains([]string{normXPath20, normXPath30, normXPath31}, r.Norm.Document) || r.Norm.Clause != "D") {
		c.problem(r.ID, "published-inventory is limited to the Appendix D documentation duty")
	}

	if proof.Oracle == normPublisher {
		if proof.Catalog == nil {
			c.problem(r.ID, "publisher evidence requires an exact catalog case")
			return
		}

		p := proof.Catalog

		c.choice(r.ID, p.Suite, "qt3", "xslt30")
		c.choice(r.ID, p.Version, "2.0", "3.0", "3.1")
		c.choice(r.ID, p.XSDVersion, "1.0", "1.1")
		c.text(r.ID, p.Name, p.File)

		if filepath.IsAbs(p.File) || strings.Contains(p.File, "\\") || filepath.Clean(p.File) != p.File || strings.HasPrefix(p.File, "../") {
			c.problem(r.ID, "catalog evidence requires a portable relative file")
		}

		if p.Suite == "xslt30" && p.Version == "3.1" {
			c.problem(r.ID, "XSLT has no 3.1 processor edition")
		}

		if proof.Check.File != "tests/cmd/dev/main_test.go" || proof.Check.Name != "TestLanguageNormativeEvidence" || proof.Check.Case != r.ID+"/"+p.Name {
			c.problem(r.ID, "publisher witness must name its exact executing subtest")
		}
	} else if proof.Catalog != nil {
		c.problem(r.ID, "processor or published-vector evidence cannot masquerade as a publisher case")
	}
}

func (c *conformanceCheck) document(document standardDocument) {
	if _, exists := c.documents[document.ID]; document.ID == "" || exists {
		c.problem(document.ID, "empty/duplicate document ID")
	}

	c.documents[document.ID] = document
	c.text(document.ID, document.Title, document.Edition, document.Errata.Notes)
	c.webURL(document.ID, document.Source)
	c.choice(document.ID, document.Errata.Review, "reviewed", conformancePartial, conformancePending)

	if _, err := time.Parse(time.DateOnly, document.Errata.ReviewedOn); err != nil {
		c.problem(document.ID, "errata reviewed_on must be an ISO date")
	}

	corrections := make(map[string]bool)
	for _, item := range document.Errata.Items {
		if item.ID == "" || corrections[item.ID] {
			c.problem(document.ID, "empty/duplicate correction ID")
		}

		corrections[item.ID] = true
		c.text(document.ID, item.Clause, item.Reason)
		c.choice(document.ID, item.Disposition, "selected", "incorporated", "proposed", "informative", "rejected", "held", "other-role")
	}

	for _, source := range document.Errata.Sources {
		c.webURL(document.ID, source)
	}
}

func (c *conformanceCheck) profile(profile conformanceProfile) {
	if _, exists := c.profiles[profile.ID]; profile.ID == "" || exists {
		c.problem(profile.ID, "empty/duplicate profile ID")
	}

	c.profiles[profile.ID] = profile
	c.text(profile.ID, profile.Title, profile.Role)
	c.choice(profile.ID, profile.Claim, "restricted", "target", conformanceFull)
	c.choice(profile.ID, profile.Inventory, conformancePartial, "complete")
	c.unique(profile.ID, profile.Modes)
	c.unique(profile.ID, profile.Documents)
	c.unique(profile.ID, profile.ScopeIDs)

	if len(profile.Modes) == 0 || len(profile.Documents) == 0 || len(profile.PackageDocs) == 0 {
		c.problem(profile.ID, "profile requires modes, documents and package docs")
	}

	if profile.Inventory != conformanceComplete || profile.Claim == "target" {
		c.text(profile.ID, profile.Gap, profile.Closure)
	}

	if profile.Claim == conformanceFull && (profile.Inventory != conformanceComplete || profile.Gap != "") {
		c.problem(profile.ID, "full claim requires a complete inventory without a gap")
	}

	for _, id := range profile.Documents {
		document, exists := c.documents[id]
		if !exists {
			c.problem(profile.ID, "unknown document "+id)
		} else if profile.Claim == conformanceFull && document.Errata.Review != "reviewed" {
			c.problem(profile.ID, "full claim requires reviewed errata for "+id)
		}
	}

	for _, id := range profile.ScopeIDs {
		if !c.scopes[id] {
			c.problem(profile.ID, "unknown capability "+id)
		}
	}

	for _, path := range profile.PackageDocs {
		c.path(profile.ID, path)
	}
}

func (c *conformanceCheck) matrix(profile conformanceProfile, requirements map[string]normativeRequirement) {
	documents := make(map[string]bool)
	linked := make(map[string]bool)
	modes := make(map[string]bool)
	unmapped := false

	for _, row := range profile.Matrix {
		if documents[row.Document] || !slices.Contains(profile.Documents, row.Document) {
			c.problem(profile.ID, "duplicate/unknown matrix document "+row.Document)
		}

		documents[row.Document] = true
		c.matrixRow(profile, row)

		for _, id := range row.Requirements {
			r, exists := requirements[id]
			if !exists || r.Applies.Profile != profile.ID || r.Norm.Document != row.Document || !slices.Contains(row.Modes, r.Applies.Mode) {
				c.problem(profile.ID, "missing or mismatched matrix requirement "+id)
				continue
			}

			linked[id], modes[r.Applies.Mode] = true, true
		}

		if len(row.Unmapped) > 0 {
			unmapped = true

			c.text(profile.ID, row.Closure)

			if profile.Inventory == conformanceComplete {
				c.problem(profile.ID, "complete inventory has unmapped clauses")
			}
		}
	}

	for _, document := range profile.Documents {
		if !documents[document] {
			c.problem(profile.ID, "document missing from role matrix: "+document)
		}
	}

	for _, mode := range profile.Modes {
		if !modes[mode] {
			c.problem(profile.ID, "mode has no assessed normative obligation: "+mode)
		}
	}

	for id, r := range requirements {
		if r.Applies.Profile == profile.ID && !linked[id] {
			c.problem(profile.ID, "normative obligation missing from matrix: "+id)
		}
	}

	if profile.Inventory == conformancePartial && !unmapped {
		c.problem(profile.ID, "partial inventory must identify unmapped clauses")
	}
}

func (c *conformanceCheck) matrixRow(profile conformanceProfile, row profileMatrix) {
	c.text(profile.ID, row.Reason)
	c.unique(profile.ID, row.Modes)
	c.unique(profile.ID, row.Requirements)
	c.unique(profile.ID, row.Unmapped)

	if len(row.Modes) == 0 || len(row.Requirements)+len(row.Unmapped) == 0 {
		c.problem(profile.ID, "matrix row requires modes and assessed or unmapped clauses")
	}

	for _, mode := range row.Modes {
		if !slices.Contains(profile.Modes, mode) {
			c.problem(profile.ID, "matrix mode is not part of the selected profile")
		}
	}
}

func (c *conformanceCheck) normativeSource(r normativeRequirement) {
	c.webURL(r.ID, r.Norm.Source)

	u, err := url.Parse(r.Norm.Source)
	if err == nil {
		u.Fragment, u.RawFragment = "", ""
		if strings.TrimRight(u.String(), "/") != strings.TrimRight(c.documents[r.Norm.Document].Source, "/") {
			c.problem(r.ID, "normative source must belong to the pinned document")
		}
	}

	c.unique(r.ID, r.Norm.Errata)

	for _, id := range r.Norm.Errata {
		if !slices.ContainsFunc(c.documents[r.Norm.Document].Errata.Items, func(item standardCorrection) bool {
			return item.ID == id && (item.Disposition == "selected" || item.Disposition == "incorporated")
		}) {
			c.problem(r.ID, "unknown or unselected correction "+id)
		}
	}
}

func (c *conformanceCheck) unique(id string, values []string) {
	seen := make(map[string]bool)
	for _, value := range values {
		if strings.TrimSpace(value) == "" || seen[value] {
			c.problem(id, "empty/duplicate matrix, mode, document or correction entry")
		}

		seen[value] = true
	}
}

func (c *conformanceCheck) requirement(r normativeRequirement) {
	c.text(r.ID, r.Statement, r.Norm.Document, r.Norm.Clause, r.Applies.Role, r.Applies.Mode, r.Applies.Reason)
	c.choice(r.ID, r.Norm.Level, "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", "REQUIRED", "RECOMMENDED", "OPTIONAL", "normative", "informative")
	c.choice(r.ID, r.Applies.Status, "applicable", normNotApplicable)
	c.choice(r.ID, r.Implementation.Status, normImplemented, "limited", "unimplemented", normNotApplicable)
	c.choice(r.ID, r.Interop.Status, conformanceCovered, conformancePending, normNotApplicable)
	c.text(r.ID, r.Interop.Reason)

	profile, exists := c.profiles[r.Applies.Profile]
	if !exists || !slices.Contains(profile.Documents, r.Norm.Document) {
		c.problem(r.ID, "unknown profile/document association")
	}

	if !slices.Contains(profile.Modes, r.Applies.Mode) {
		c.problem(r.ID, "mode is not part of the selected profile")
	}

	c.normativeSource(r)
	c.requirementRole(r, profile)

	if r.Implementation.Status == normImplemented || r.Implementation.Status == "limited" {
		if len(r.Implementation.APIs) == 0 || len(r.Implementation.Code) == 0 {
			c.problem(r.ID, "supported requirement needs APIs and code")
		}
	}

	c.localEvidence(r)

	if r.Implementation.Status != normImplemented && r.Implementation.Status != normNotApplicable || r.Interop.Status == conformancePending || r.Tests.Status == conformancePending || r.Tests.Status == conformancePartial {
		c.text(r.ID, r.Gap, r.Closure)
	}

	optional := r.Norm.Level == "MAY" || r.Norm.Level == "OPTIONAL"
	if profile.Claim == conformanceFull && !optional && r.Applies.Status == "applicable" && (r.Implementation.Status != normImplemented || r.Gap != "" || r.Interop.Status == conformancePending || r.Tests.Status != conformanceCovered) {
		c.problem(r.ID, "an open obligation prevents a full claim")
	}

	if r.Interop.Status == conformanceCovered && (len(r.Interop.Tests) == 0 || len(r.Interop.Fixtures) == 0) {
		c.problem(r.ID, "covered interoperability requires checks and independent fixtures")
	}

	c.requirementEvidence(r)
}

func (c *conformanceCheck) requirementRole(r normativeRequirement, profile conformanceProfile) {
	if r.Norm.Level == "informative" && (r.Applies.Status != normNotApplicable || r.Applies.Role != "informative-reference") || r.Applies.Role == "informative-reference" && r.Norm.Level != "informative" {
		c.problem(r.ID, "informative material must remain a distinct non-applicable reference role")
	}

	if slices.Contains([]string{normXPath20, normXPath30, normXPath31}, r.Norm.Document) && r.Norm.Clause == "D" {
		data, err := os.ReadFile(filepath.Join(c.root, "docs", "transforms.md"))
		if err == nil {
			err = checkXPathHostChoiceDocumentation(string(data), strings.TrimPrefix(r.Norm.Document, "XP"))
		}

		if err != nil {
			c.problem(r.ID, "published host-choice inventory: "+err.Error())
		}
	}

	if r.Applies.Status == normNotApplicable {
		if r.Implementation.Status != normNotApplicable || r.Applies.Role == profile.Role {
			c.problem(r.ID, "non-applicability requires a different standard role, not missing code or a policy prohibition")
		}
	} else if r.Implementation.Status == normNotApplicable || r.Applies.Role != profile.Role {
		c.problem(r.ID, "applicable requirement must match the selected role")
	}
}

// These declarations account for the finite Appendix D publication duty, not
// portable defaults that another host is required to choose identically.
func xpathHostChoiceDeclarations(version string) map[string]string {
	choices := map[string]string{
		"unicode-version":    "Unicode properties use Unicode 17.0",
		"known-collations":   "Known collation URI families are Unicode codepoint",
		"implicit-timezone":  "explicit implicit timezones use whole minutes within ±14 hours",
		"warnings":           "Warnings are not emitted",
		"error-transport":    "Errors are returned as `transform.Error`",
		"xml-names-editions": "Names use XML 1.0 Fifth Edition and Namespaces 1.0 Third Edition",
		"namespace-axis":     "The namespace axis is supported",
		"static-typing":      "Static typing is not enabled",
	}

	if version != "20" {
		for key, value := range map[string]string{
			"non-infoset-construction": "Non-XML input comes from caller-built document trees and public `Value`/`Sequence`",
			"schema-type-system":       "`XMLSchemaVersion` selects 1.0 or 1.1 datatype",
			"extension-signatures":     "have their registered arity and generic `item()*` argument/result types",
			"environment-variables":    "come only from the copied `Config.Environment` map",
			"serialization-parameters": "Serialization occurs through explicit",
			"external-result-mismatch": "invalid external-function results retain their type error",
		} {
			choices[key] = value
		}
	}

	return choices
}

func checkXPathHostChoiceDocumentation(text, version string) error {
	var missing []error

	for item, declaration := range xpathHostChoiceDeclarations(version) {
		if !strings.Contains(text, declaration) {
			missing = append(missing, fmt.Errorf("%s is not documented", item))
		}
	}

	return errors.Join(missing...)
}

func (c *conformanceCheck) localEvidence(r normativeRequirement) {
	c.choice(r.ID, r.Tests.Status, conformanceCovered, conformancePartial, conformancePending, normNotApplicable)
	c.text(r.ID, r.Tests.Reason)

	checks := len(r.Tests.Positive) + len(r.Tests.Negative)
	switch r.Tests.Status {
	case conformanceCovered:
		if len(r.Tests.Positive) == 0 || len(r.Tests.Negative) == 0 {
			c.problem(r.ID, "covered local evidence requires positive/negative tests")
		}
	case conformancePartial:
		if checks == 0 {
			c.problem(r.ID, "partial local evidence requires named checks")
		}
	case conformancePending:
		if checks != 0 {
			c.problem(r.ID, "pending local evidence must not claim named checks; use partial")
		}
	case normNotApplicable:
		if checks != 0 || r.Applies.Status != normNotApplicable {
			c.problem(r.ID, "non-applicable evidence requires a different standard role without test claims")
		}
	}
}

func (c *conformanceCheck) requirementEvidence(r normativeRequirement) {
	for _, path := range append(slices.Clone(r.Implementation.Code), r.Interop.Fixtures...) {
		c.path(r.ID, path)
	}

	for _, api := range r.Implementation.APIs {
		c.api(r.ID, api)
	}

	for _, tests := range [][]conformanceTest{r.Tests.Positive, r.Tests.Negative, r.Interop.Tests} {
		for _, test := range tests {
			c.test(r.ID, test)
		}
	}

	for _, permission := range []policyPermission{r.Policy.Default, r.Policy.Compatibility} {
		c.choice(r.ID, permission.Status, "enabled", "opt-in", "forbidden", "unavailable", normNotApplicable)
		c.text(r.ID, permission.Reason)

		if r.Implementation.Status == "unimplemented" && (permission.Status == "enabled" || permission.Status == "opt-in") {
			c.problem(r.ID, "policy cannot enable an unimplemented capability")
		}
	}
}

func (c *conformanceCheck) test(id string, test conformanceTest) {
	if !strings.HasSuffix(test.File, "_test.go") || !strings.HasPrefix(test.Name, "Test") {
		c.problem(id, "evidence must identify a Go test function")
		return
	}

	path, err := localPath(c.root, c.root, filepath.FromSlash(test.File))
	if err != nil {
		c.problem(id, "invalid test path: "+err.Error())
		return
	}

	symbols, parsed := c.symbols[path]
	if !parsed {
		symbols = make(map[string]bool)
		c.symbols[path] = symbols

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			c.problem(id, "cannot parse test: "+err.Error())
			return
		}

		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && conformanceTestFunction(file, fn) {
				symbols[fn.Name.Name] = true
			}
		}
	}

	if !symbols[test.Name] {
		c.problem(id, "missing test "+test.File+":"+test.Name)
	}
}

func conformanceTestFunction(file *ast.File, fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Type.TypeParams != nil || fn.Type.Results != nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}

	parameter := fn.Type.Params.List[0]
	if len(parameter.Names) > 1 {
		return false
	}

	pointer, ok := parameter.Type.(*ast.StarExpr)
	if !ok {
		return false
	}

	for _, imported := range file.Imports {
		if imported.Path.Value != `"testing"` {
			continue
		}

		alias := "testing"
		if imported.Name != nil {
			alias = imported.Name.Name
		}

		if alias == "." {
			name, ok := pointer.X.(*ast.Ident)
			return ok && name.Name == "T"
		}

		selector, ok := pointer.X.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "T" {
			return false
		}

		name, ok := selector.X.(*ast.Ident)

		return ok && name.Name == alias
	}

	return false
}

func (c *conformanceCheck) api(id, reference string) {
	packagePath, symbol, ok := strings.Cut(reference, ".")
	if !ok || symbol == "" {
		c.problem(id, "API must name package.Symbol or package.Type.Member")
		return
	}

	dir, err := localPath(c.root, c.root, filepath.FromSlash(packagePath))
	if err != nil {
		c.problem(id, "invalid API package: "+err.Error())
		return
	}

	symbols, parsed := c.symbols[dir]
	if !parsed {
		symbols = make(map[string]bool)
		c.symbols[dir] = symbols

		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			c.problem(id, "cannot list API files: "+err.Error())
			return
		}

		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}

			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				c.problem(id, "cannot parse API: "+err.Error())
				return
			}

			collectConformanceAPIs(file, symbols)
		}
	}

	if !symbols[symbol] {
		c.problem(id, "missing exported API "+reference)
	}
}

func collectConformanceAPIs(file *ast.File, symbols map[string]bool) {
	ast.Inspect(file, func(node ast.Node) bool {
		switch decl := node.(type) {
		case *ast.FuncDecl:
			if name := conformanceAPIName(decl); name != "" {
				symbols[name] = true
			}

			return false
		case *ast.TypeSpec:
			collectConformanceType(decl, symbols)

			return false
		}

		return true
	})
}

func conformanceAPIName(decl *ast.FuncDecl) string {
	if !ast.IsExported(decl.Name.Name) {
		return ""
	}

	if decl.Recv == nil {
		return decl.Name.Name
	}

	receiver := decl.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}

	if owner, ok := receiver.(*ast.Ident); ok && ast.IsExported(owner.Name) {
		return owner.Name + "." + decl.Name.Name
	}

	return ""
}

func collectConformanceType(decl *ast.TypeSpec, symbols map[string]bool) {
	if !ast.IsExported(decl.Name.Name) {
		return
	}

	symbols[decl.Name.Name] = true

	structure, ok := decl.Type.(*ast.StructType)
	if !ok {
		return
	}

	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			if ast.IsExported(name.Name) {
				symbols[decl.Name.Name+"."+name.Name] = true
			}
		}
	}
}

func (c *conformanceCheck) path(id, path string) {
	if path == "" {
		c.problem(id, "empty evidence/code path")
		return
	}

	if err := checkConformanceTest(c.root, path); err != nil {
		c.problem(id, "missing/nonportable file "+path+": "+err.Error())
	}
}

func (c *conformanceCheck) webURL(id, source string) {
	u, err := url.Parse(source)
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" {
		c.problem(id, "source must be an absolute HTTPS URL")
	}
}

func (c *conformanceCheck) text(id string, values ...string) {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			c.problem(id, "missing required description or closure criterion")
		}
	}
}

func (c *conformanceCheck) choice(id, value string, allowed ...string) {
	if !slices.Contains(allowed, value) {
		c.problem(id, "unknown state "+value)
	}
}

func (c *conformanceCheck) problem(id, message string) {
	c.problems = append(c.problems, fmt.Errorf("conformance %s: %s", id, message))
}
