package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/encoding/charmap"

	"github.com/skarm/xmlsec/internal/lexicon"
	"github.com/skarm/xmlsec/transform"
)

const suiteXSLTNamespace = "http://www.w3.org/2012/10/xslt-test-catalog"

const (
	suiteVersion10          = "1.0"
	suiteVersion11          = "1.1"
	suiteCatalog            = "catalog.xml"
	suiteHarnessFailure     = "harness"
	suiteResourceLimit      = "resource-limit"
	suiteSecondary          = "secondary"
	suiteQT3                = "qt3"
	suiteXSLT               = "xslt30"
	suiteVersion20          = "2.0"
	suiteVersion30          = "3.0"
	suiteVersion31          = "3.1"
	suiteResultVariable     = "result"
	suiteTrue               = "true"
	suiteDirectoryFlag      = "-dir"
	suitePassed             = "passed"
	suiteFailed             = "failed"
	suiteSkipped            = "skipped"
	suiteNotApplicable      = "not-applicable"
	suiteMaxFileBytes       = 16 << 20
	suiteLanguage           = "language"
	suiteFile               = "file"
	suiteNamespace          = "namespace"
	suitePackageTag         = "package"
	suiteOutput             = "output"
	suiteParam              = "param"
	suiteYes                = "yes"
	suiteVersion            = "version"
	suiteDefaultCurrentTime = "2026-01-01T00:00:00Z"
)

type suitePin struct {
	Repository       string `json:"repository"`
	Revision         string `json:"revision"`
	Catalog          string `json:"catalog"`
	Namespace        string `json:"namespace"`
	License          string `json:"license"`
	LicenseReference string `json:"license_reference"`
	Use              string `json:"use"`
}

type suiteOptions struct {
	kind, directory, version, report string
	limitsProfile                    string
	xsdVersion                       string
	xpath10Compatibility             bool
	xsltAssertions                   bool
	setMatch, caseMatch              *regexp.Regexp
	limit                            int
	timeout                          time.Duration
	currentTime                      time.Time
}

type suiteOutcome struct {
	Set              string `json:"set"`
	Name             string `json:"name"`
	File             string `json:"file"`
	Status           string `json:"status"`
	Kind             string `json:"kind,omitempty"`
	Reason           string `json:"reason,omitempty"`
	ExecutionVersion string `json:"execution_version,omitempty"`
}

type suiteReport struct {
	Suite            string         `json:"suite"`
	Pin              suitePin       `json:"pin"`
	Language         string         `json:"language"`
	Go               string         `json:"go"`
	Platform         string         `json:"platform"`
	LibraryRevision  string         `json:"library_revision"`
	LibraryModified  bool           `json:"library_modified"`
	SourceSHA256     string         `json:"source_sha256"`
	ExecutableSHA256 string         `json:"executable_sha256"`
	Settings         map[string]any `json:"settings"`
	Totals           map[string]int `json:"totals"`
	Cases            []suiteOutcome `json:"cases"`
}

// The catalog decoder never resolves external entities or executes catalog code.
type suiteNode struct {
	XMLName    xml.Name
	Attributes []xml.Attr   `xml:",any,attr"`
	Text       string       `xml:",chardata"`
	Children   []*suiteNode `xml:",any"`
	namespaces map[string]string
	baseURI    string
}

func (n *suiteNode) attr(name string) string {
	if n != nil {
		for _, attribute := range n.Attributes {
			if attribute.Name.Space == "" && attribute.Name.Local == name {
				return attribute.Value
			}
		}
	}

	return ""
}

func (n *suiteNode) child(name string) *suiteNode {
	if n != nil {
		for _, child := range n.Children {
			if child.XMLName.Local == name {
				return child
			}
		}
	}

	return nil
}

func (n *suiteNode) children(name string) []*suiteNode {
	var result []*suiteNode

	if n != nil {
		for _, child := range n.Children {
			if child.XMLName.Local == name {
				result = append(result, child)
			}
		}
	}

	return result
}

func runSuites(ctx context.Context, root string, args []string, out, stderr io.Writer) error {
	options, err := parseSuiteOptions(args, stderr)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Join(root, "build", "w3c-suites.json")) // #nosec G304 -- Fixed repository-relative configuration, not a catalog-derived path.
	if err != nil {
		return err
	}

	var pins map[string]suitePin
	if err := json.Unmarshal(raw, &pins); err != nil {
		return err
	}

	pin, ok := pins[options.kind]
	if !ok {
		return errors.New("suite must be qt3 or xslt30")
	}

	if err := verifySuiteCheckout(ctx, options.directory, pin); err != nil {
		return err
	}

	revision, err := suiteGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return err
	}

	sourceDigest, err := suiteSourceDigest(ctx, root)
	if err != nil {
		return err
	}

	report, err := executeSuite(ctx, options, pin)
	if err != nil {
		return err
	}

	report.LibraryRevision = strings.TrimSpace(revision)

	report.SourceSHA256, err = suiteSourceDigest(ctx, root)
	if err != nil {
		return err
	}

	if report.SourceSHA256 != sourceDigest {
		return errors.New("library sources changed during the suite run; rerun with stable sources")
	}

	if err := verifySuiteCheckout(ctx, options.directory, pin); err != nil {
		return err
	}

	status, err := suiteGit(ctx, root, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}

	report.LibraryModified = strings.TrimSpace(status) != ""

	report.ExecutableSHA256, err = suiteExecutableDigest()
	if err != nil {
		return err
	}

	if err := writeSuiteReport(options.report, out, report); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stderr, "%s %s: passed=%d failed=%d skipped=%d not-applicable=%d\n", options.kind, options.version, report.Totals[suitePassed], report.Totals[suiteFailed], report.Totals[suiteSkipped], report.Totals[suiteNotApplicable]); err != nil {
		return err
	}

	if report.Totals[suiteFailed] > 0 {
		return fmt.Errorf("%d applicable cases failed; see implementation/assertion/harness reasons in the report", report.Totals[suiteFailed])
	}

	if report.Totals[suitePassed] == 0 {
		return errors.New("no selected applicable case passed")
	}

	return nil
}

func suiteSourceDigest(ctx context.Context, root string) (string, error) {
	listing, err := suiteGit(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.go", "go.mod", "go.sum", "build/w3c-suites.json")
	if err != nil {
		return "", err
	}

	paths := strings.Split(strings.TrimSuffix(listing, "\x00"), "\x00")
	sort.Strings(paths)

	digest := sha256.New()

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		raw, _, err := readSuiteFile(root, root, path)
		if err != nil {
			return "", err
		}

		_, _ = digest.Write([]byte(path + "\x00" + strconv.Itoa(len(raw)) + "\x00"))
		_, _ = digest.Write(raw)
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

func suiteLimits(options suiteOptions) transform.Limits {
	limits := transform.DefaultLimits()
	if options.limitsProfile == suiteLanguage {
		limits.MaxInputBytes, limits.MaxResourceBytes = 32<<20, 64<<20
		limits.MaxProgramBytes, limits.MaxOutputBytes = 1<<20, 64<<20
		limits.MaxNodes, limits.MaxOperations = 2_000_000, 50_000_000
	}

	return limits
}

func suiteExecutableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}

	file, err := os.Open(path) // #nosec G304 -- The running executable's path comes from the runtime, not suite metadata.
	if err != nil {
		return "", err
	}

	digest := sha256.New()

	_, readErr := io.Copy(digest, file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return "", err
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

func parseSuiteOptions(args []string, stderr io.Writer) (suiteOptions, error) {
	var options suiteOptions

	flags := flag.NewFlagSet("suites", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.kind, "suite", suiteQT3, "qt3 or xslt30")
	flags.StringVar(&options.directory, "dir", "", "unmodified checkout at the pinned revision")
	flags.StringVar(&options.version, suiteVersion, suiteVersion31, "XPath 2.0/3.0/3.1 or XSLT 2.0/3.0")
	flags.StringVar(&options.report, "report", "", "JSON report file; empty writes stdout")
	flags.StringVar(&options.limitsProfile, "limits", "default", "default or language; explicit development budgets, never unbounded")
	flags.StringVar(&options.xsdVersion, "xsd-version", suiteVersion10, "builtin datatype and regex edition: 1.0 or 1.1; schema validation stays disabled")
	flags.BoolVar(&options.xsltAssertions, "assertions", false, "enable XSLT assertion checking in direct and nested transforms")
	flags.BoolVar(&options.xpath10Compatibility, "xpath10-compatibility", false, "enable the XPath 1.0 compatibility property for modern QT3 expressions")
	setPattern := flags.String("sets", ".*", "test-set name pattern")
	casePattern := flags.String("match", ".*", "test-case name pattern")
	flags.IntVar(&options.limit, "limit", 0, "selected-case limit; remaining cases are explicitly skipped")
	flags.DurationVar(&options.timeout, "timeout", time.Second, "per-case wall-clock budget")
	currentTime := flags.String("current-time", suiteDefaultCurrentTime, "fixed RFC3339 dynamic-context time shared by cases and assertions")

	if err := flags.Parse(args); err != nil {
		return options, err
	}

	if flags.NArg() != 0 || options.directory == "" || options.limit < 0 || options.timeout <= 0 {
		return options, errors.New("a suite directory, positive timeout and nonnegative limit are required; no positional arguments")
	}

	validVersion := options.version == suiteVersion20 || options.version == suiteVersion30 || options.version == suiteVersion31 && options.kind == suiteQT3
	if !validVersion {
		return options, errors.New("select XPath 2.0/3.0/3.1 or XSLT 2.0/3.0")
	}

	if options.limitsProfile != "default" && options.limitsProfile != suiteLanguage {
		return options, errors.New("limits must be default or language")
	}

	if options.xsdVersion != suiteVersion10 && options.xsdVersion != suiteVersion11 {
		return options, errors.New("xsd-version must be 1.0 or 1.1")
	}

	if options.kind != suiteQT3 && options.xpath10Compatibility {
		return options, errors.New("xpath10-compatibility applies only to QT3; XSLT uses stylesheet-local version modes")
	}

	var err error

	options.currentTime, err = time.Parse(time.RFC3339Nano, *currentTime)
	if err != nil {
		return options, fmt.Errorf("current-time must be RFC3339: %w", err)
	}

	options.currentTime = options.currentTime.UTC()

	if options.setMatch, err = regexp.Compile(*setPattern); err != nil {
		return options, err
	}

	if options.caseMatch, err = regexp.Compile(*casePattern); err != nil {
		return options, err
	}

	options.directory, err = filepath.EvalSymlinks(options.directory)
	if err != nil {
		return options, err
	}

	options.directory, err = filepath.Abs(options.directory)

	return options, err
}

func suiteGit(ctx context.Context, directory string, args ...string) (string, error) {
	arguments := append([]string{"-C", directory}, args...)
	command := exec.CommandContext(ctx, "git", arguments...) // #nosec G204 -- Fixed Git subcommands, explicit argv and no shell.

	data, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("suite Git metadata: %w", err)
	}

	return string(data), nil
}

func verifySuiteCheckout(ctx context.Context, directory string, pin suitePin) error {
	revision, err := suiteGit(ctx, directory, "rev-parse", "HEAD")
	if err != nil {
		return err
	}

	if strings.TrimSpace(revision) != pin.Revision {
		return fmt.Errorf("suite revision %s differs from pinned %s", strings.TrimSpace(revision), pin.Revision)
	}

	status, err := suiteGit(ctx, directory, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return err
	}

	if strings.TrimSpace(status) != "" {
		return errors.New("suite checkout is modified; run against unmodified pinned test material")
	}

	return nil
}

func readSuiteFile(root, base, name string) ([]byte, string, error) {
	return readSuiteFileLimit(root, base, name, suiteMaxFileBytes)
}

func readSuiteFileLimit(root, base, name string, maximum int) ([]byte, string, error) {
	path, err := localPath(root, base, filepath.FromSlash(name))
	if err != nil {
		return nil, "", err
	}

	file, err := os.Open(path) // #nosec G304 -- localPath resolves symlinks and confines the explicit file to the suite checkout.
	if err != nil {
		return nil, "", err
	}

	data, readErr := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, "", err
	}

	if len(data) > maximum {
		return nil, "", fmt.Errorf("suite file exceeds the %d-byte harness input limit", maximum)
	}

	return data, path, nil
}

func readSuiteNode(root, base, name string) (*suiteNode, string, error) {
	data, path, err := readSuiteFile(root, base, name)
	if err != nil {
		return nil, "", err
	}

	var node suiteNode

	decoder := xml.NewDecoder(bytes.NewReader(data)) // #nosec G709 -- Bounded local catalog; encoding/xml does not resolve external entities or execute type constructors.

	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "iso-8859-1") {
			return charmap.ISO8859_1.NewDecoder().Reader(input), nil
		}

		if !strings.EqualFold(charset, "us-ascii") && !strings.EqualFold(charset, "ascii") {
			return nil, fmt.Errorf("unsupported suite catalog encoding %q", charset)
		}

		for _, value := range data {
			if value > 0x7f {
				return nil, errors.New("non-ASCII byte in an ASCII catalog")
			}
		}

		return input, nil
	}
	if err := decoder.Decode(&node); err != nil {
		return nil, "", fmt.Errorf("suite catalog XML: %w", err)
	}

	if err := bindSuiteStaticContext(&node, nil, suiteFileURI(path)); err != nil {
		return nil, "", err
	}

	return &node, path, nil
}

func bindSuiteStaticContext(node *suiteNode, inherited map[string]string, baseURI string) error {
	node.baseURI = baseURI
	for _, attribute := range node.Attributes {
		if attribute.Name.Space == lexicon.NamespaceXML && attribute.Name.Local == "base" {
			base, err := url.Parse(baseURI)
			if err != nil {
				return err
			}

			ref, err := url.Parse(attribute.Value)
			if err != nil {
				return err
			}

			node.baseURI = base.ResolveReference(ref).String()
		}
	}

	node.namespaces = inherited
	for _, attribute := range node.Attributes {
		if attribute.Name.Space == "xmlns" {
			node.namespaces = make(map[string]string, len(inherited)+1)
			maps.Copy(node.namespaces, inherited)
			suiteNamespaceDeclarations(node, node.namespaces)

			break
		}
	}

	for _, child := range node.Children {
		if err := bindSuiteStaticContext(child, node.namespaces, node.baseURI); err != nil {
			return err
		}
	}

	return nil
}

func writeSuiteReport(path string, out io.Writer, report *suiteReport) error {
	if path == "" {
		return json.NewEncoder(out).Encode(report)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(data, '\n'), 0o600) // #nosec G306,G703 -- Explicit caller-chosen CLI output, never a catalog-derived path; private permissions.
}

type suiteCase struct {
	set, file, base string
	setNode, node   *suiteNode
	environments    map[string]suiteEnvironmentRef
}

type suiteEnvironmentRef struct {
	node *suiteNode
	base string
}

func executeSuite(ctx context.Context, options suiteOptions, pin suitePin) (*suiteReport, error) {
	catalog, _, err := readSuiteNode(options.directory, options.directory, pin.Catalog)
	if err != nil {
		return nil, err
	}

	if catalog.XMLName.Space != pin.Namespace || catalog.XMLName.Local != "catalog" {
		return nil, errors.New("unexpected suite catalog namespace or root")
	}

	report := &suiteReport{
		Suite:    options.kind,
		Pin:      pin,
		Language: options.version,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Totals:   map[string]int{suitePassed: 0, suiteFailed: 0, suiteSkipped: 0, suiteNotApplicable: 0},
		Settings: map[string]any{
			"limits":                      suiteLimits(options),
			"limits_profile":              options.limitsProfile,
			"case_timeout":                options.timeout.String(),
			"current_time":                suiteDynamicContext(options.currentTime).CurrentTime.Format(time.RFC3339Nano),
			"implicit_timezone":           "UTC",
			"default_language":            "en",
			"default_collation":           "Unicode codepoint",
			"schema_aware":                false,
			"xsd_version":                 suiteXSDVersionName(options),
			"xpath_1_0_compatibility":     options.xpath10Compatibility,
			"xslt_assertions":             options.xsltAssertions,
			"unicode_version":             unicode.Version,
			"w3c_streaming":               false,
			"assertion_language":          "XPath 3.1 through the public engine",
			"network":                     false,
			"allow_single_byte_encodings": true,
			"set_pattern":                 options.setMatch.String(),
			"case_pattern":                options.caseMatch.String(),
			"case_limit":                  options.limit,
		},
	}
	selected := 0

	for _, entry := range catalog.children("test-set") {
		set, path, err := readSuiteNode(options.directory, options.directory, entry.attr(suiteFile))
		if err != nil {
			return nil, err
		}

		if set.XMLName.Space != pin.Namespace || set.XMLName.Local != "test-set" {
			return nil, errors.New("unexpected test-set namespace or root")
		}

		environments := suiteEnvironments(catalog, options.directory, nil)
		environments = suiteEnvironments(set, filepath.Dir(path), environments)

		for _, node := range set.children("test-case") {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			item := suiteCase{set: entry.attr("name"), file: entry.attr(suiteFile), base: filepath.Dir(path), setNode: set, node: node, environments: environments}

			outcome := suiteOutcome{Set: item.set, File: item.file, Name: node.attr("name")}
			if !options.setMatch.MatchString(item.set) || !options.caseMatch.MatchString(outcome.Name) {
				outcome.Status, outcome.Reason = suiteSkipped, "not selected by the explicit set/case filter"
			} else if options.limit > 0 && selected >= options.limit {
				outcome.Status, outcome.Reason = suiteSkipped, "explicit selected-case limit reached"
			} else {
				selected++
				outcome = executeSuiteCase(ctx, options, item, outcome)
			}

			report.Cases = append(report.Cases, outcome)
			report.Totals[outcome.Status]++
		}
	}

	return report, nil
}

func suiteEnvironments(node *suiteNode, base string, previous map[string]suiteEnvironmentRef) map[string]suiteEnvironmentRef {
	result := make(map[string]suiteEnvironmentRef, len(previous))
	maps.Copy(result, previous)

	for _, environment := range node.children("environment") {
		result[environment.attr("name")] = suiteEnvironmentRef{node: environment, base: base}
	}

	return result
}

func executeSuiteCase(parent context.Context, options suiteOptions, item suiteCase, outcome suiteOutcome) (result suiteOutcome) {
	result = outcome

	defer func() {
		if value := recover(); value != nil {
			result.Status, result.Kind, result.Reason = suiteFailed, "panic", fmt.Sprint(value)
		}
	}()

	status, reason := suiteApplicability(options, item)
	if status != "" {
		result.Status, result.Reason = status, reason
		if status == suiteFailed {
			result.Kind = "dependency"
		}

		return result
	}

	ctx, cancel := context.WithTimeout(parent, options.timeout)
	defer cancel()

	environment, err := prepareSuiteEnvironment(ctx, options, item)
	if err != nil {
		result.Status, result.Kind, result.Reason = suiteFailed, suiteHarnessFailure, err.Error()
		if suiteBudgetFailure(ctx, err) != nil {
			result.Kind = suiteResourceLimit
		}

		return result
	}

	evaluation := evaluateSuiteCase(ctx, options, item, environment)

	result.ExecutionVersion = environment.executionVersion
	if failure := suiteDeadlineFailure(ctx, evaluation.err); failure != nil {
		result.Status, result.Kind, result.Reason = suiteFailed, suiteResourceLimit, failure.Error()
		return result
	}

	assertionErr := checkSuiteAssertion(ctx, evaluation, item.node.child(suiteResultVariable))
	if failure := suiteDeadlineFailure(ctx, assertionErr); failure != nil {
		result.Status, result.Kind, result.Reason = suiteFailed, suiteResourceLimit, failure.Error()
		return result
	}

	if err := assertionErr; err != nil {
		result.Status, result.Kind, result.Reason = suiteFailed, "assertion", err.Error()

		if _, ok := errors.AsType[*suiteHarnessError](err); ok {
			result.Kind = suiteHarnessFailure
		} else if errors.Is(evaluation.err, transform.ErrLimit) || errors.Is(err, transform.ErrLimit) {
			result.Kind = suiteResourceLimit
		} else if errors.Is(evaluation.err, transform.ErrUnsupported) {
			result.Kind = "unsupported-profile"
		}
	} else {
		result.Status = suitePassed
	}

	return result
}

// Deadline expiry is a runner failure, even if an error assertion would match
// a surrounding language code. Explicit standard resource-limit alternatives
// such as XPDY0130 remain eligible for normal assertion matching.
func suiteDeadlineFailure(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ctx.Err()
	}

	return nil
}

func suiteBudgetFailure(ctx context.Context, err error) error {
	if errors.Is(err, transform.ErrLimit) {
		return err
	}

	return suiteDeadlineFailure(ctx, err)
}

type suiteHarnessError struct{ message string }

func (e *suiteHarnessError) Error() string { return "harness: " + e.message }

func suiteHarness(format string, args ...any) error {
	return &suiteHarnessError{message: fmt.Sprintf(format, args...)}
}
