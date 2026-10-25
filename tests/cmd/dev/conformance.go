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
	Gap     string `json:"gap"`
	Closure string `json:"closure"`
}

type policyPermission struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type conformanceCheck struct {
	root      string
	problems  []error
	documents map[string]standardDocument
	profiles  map[string]conformanceProfile
	scopes    map[string]bool
	symbols   map[string]map[string]bool
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

	return len(register.Requirements), c.problems, nil
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
	c.choice(r.ID, r.Norm.Level, "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY", "REQUIRED", "RECOMMENDED", "OPTIONAL", "normative")
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

	if r.Applies.Status == normNotApplicable {
		if r.Implementation.Status != normNotApplicable || r.Applies.Role == profile.Role {
			c.problem(r.ID, "non-applicability requires a different standard role, not missing code or a policy prohibition")
		}
	} else if r.Implementation.Status == normNotApplicable || r.Applies.Role != profile.Role {
		c.problem(r.ID, "applicable requirement must match the selected role")
	}

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
