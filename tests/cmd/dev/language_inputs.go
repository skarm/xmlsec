package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Inputs and generated evidence belong to a checkout-specific external cache.
// They are never inferred from an unrelated checkout or an old audit report.
type languageInputs struct {
	Environment map[string]string `json:"environment"`
	Java        string            `json:"java"`
}

func languageInputsDirectory(root string) (string, error) {
	base := os.Getenv("XMLSEC_LANGUAGE_CACHE")
	if base == "" {
		var err error

		base, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
	}

	return filepath.Join(base, "xmlsec", "language-evidence", fmt.Sprintf("%x", sha256.Sum256([]byte(root)))), nil
}

func readLanguageInputs(root string) (languageInputs, string, error) {
	directory, err := languageInputsDirectory(root)
	if err != nil {
		return languageInputs{}, "", err
	}

	raw, err := os.ReadFile(filepath.Join(directory, "inputs.json")) // #nosec G304 -- Checkout-specific developer cache.
	if err != nil {
		return languageInputs{}, directory, err
	}

	var inputs languageInputs

	err = json.Unmarshal(raw, &inputs)

	return inputs, directory, err
}

func configureLanguageInputs(ctx context.Context, root string, out io.Writer) error {
	inputs := languageInputs{Environment: make(map[string]string)}

	for _, name := range []string{"XMLSEC_QT3_DIR", "XMLSEC_XSLT_DIR", "SAXON_CLASSPATH", "SAXON20_CLASSPATH", "SERIALIZATION_SCHEMA_DIR", "JSON_SCHEMA_FILE"} {
		value := os.Getenv(name)
		if value == "" {
			return fmt.Errorf("configure requires %s", name)
		}

		inputs.Environment[name] = value
	}

	java, err := exec.LookPath("java")
	if err != nil {
		return err
	}

	inputs.Java, err = filepath.EvalSymlinks(java)
	if err != nil {
		return err
	}

	if output, err := exec.CommandContext(ctx, inputs.Java, "-version").CombinedOutput(); err != nil { // #nosec G204 -- Explicitly selected installed Java executable, without a shell.
		return fmt.Errorf("configured Java is unavailable: %s: %w", output, err)
	}

	directory, err := languageInputsDirectory(root)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}

	if err := writeLanguageProofFile(filepath.Join(directory, "inputs.json"), inputs); err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, "Configured language test inputs in", directory)

	return err
}

func languageInputEnvironment(inputs languageInputs) []string {
	environment := os.Environ()

	for name, value := range inputs.Environment {
		if explicit := os.Getenv(name); explicit != "" {
			value = explicit
		}

		environment = append(environment, name+"="+value)
	}

	return append(environment, "PATH="+filepath.Dir(inputs.Java)+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func languagePreparedDirectory(ctx context.Context, root, base string, inputs languageInputs) (string, languageProofStamp, error) {
	stamp, err := currentLanguageProofStamp(ctx, root)
	if err != nil {
		return "", stamp, err
	}
	// Bind the cache to both sources and the selected external inputs.
	resolved := languageInputs{Java: inputs.Java, Environment: make(map[string]string)}
	for name, value := range inputs.Environment {
		if explicit := os.Getenv(name); explicit != "" {
			value = explicit
		}

		resolved.Environment[name] = value
	}

	raw, err := json.Marshal(struct {
		Stamp  languageProofStamp
		Inputs languageInputs
	}{stamp, resolved})
	if err != nil {
		return "", stamp, err
	}

	return filepath.Join(base, fmt.Sprintf("%x", sha256.Sum256(raw))), stamp, nil
}

func languagePreparedReports(directory string) []string {
	files := make([]string, len(languageProofProfileKeys()))
	for i := range files {
		files[i] = filepath.Join(directory, fmt.Sprintf("suite-%02d.json", i))
	}

	return files
}

func languagePreparedValid(directory string, stamp languageProofStamp) bool {
	var artifact languageProofArtifact
	if err := readLanguageProofFile(filepath.Join(directory, "events.json"), &artifact); err != nil {
		return false
	}

	if _, err := artifact.validate(stamp); err != nil {
		return false
	}

	for _, file := range languagePreparedReports(directory) {
		var report suiteReport
		if err := readLanguageProofFile(file, &report); err != nil || report.SourceSHA256 != stamp.SourceSHA256 {
			return false
		}
	}

	return true
}

func prepareLanguageInputs(ctx context.Context, root string, out, stderr io.Writer) error {
	inputs, base, err := readLanguageInputs(root)
	if err != nil {
		return fmt.Errorf("configure the external language inputs with proof configure: %w", err)
	}

	directory, stamp, err := languagePreparedDirectory(ctx, root, base, inputs)
	if err != nil {
		return err
	}

	if languagePreparedValid(directory, stamp) {
		_, err = fmt.Fprintln(out, "Current language evidence is cached in", directory)
		return err
	}

	work, err := os.MkdirTemp(base, "preparing-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()

	_, _ = fmt.Fprintln(out, "Preparing language evidence for the current sources; external comparisons and thirteen complete catalogs may take several minutes.")
	environment := languageInputEnvironment(inputs)
	environment = append(environment, "XMLSEC_REQUIRE_P3_PROOFS=1")

	program, err := os.Executable()
	if err != nil {
		return err
	}

	command := func(args ...string) error {
		cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 G702 -- This development command reexecutes its own binary with fixed task arguments; no shell is involved.
		cmd.Dir, cmd.Env = root, environment
		cmd.Stdout, cmd.Stderr = out, stderr

		return cmd.Run()
	}

	streams := []string{filepath.Join(work, "native.json"), filepath.Join(work, "residuals.json")}
	if err := command("proof", "capture", "-out", streams[0], "--", "-timeout=10m", "-skip=^Test(Language(NormativeEvidence|ResidualCoverage)|(QT3|XSLT)ResidualCauses)$", "./..."); err != nil {
		return err
	}

	if err := command("proof", "capture", "-out", streams[1], "--", "-timeout=10m", "-run=^Test(QT3|XSLT)ResidualCauses$", "./tests/cmd/dev"); err != nil {
		return err
	}

	patterns, err := languageIndependentPatterns(root)
	if err != nil {
		return err
	}
	// Independent test functions use separate temporary resources. Four Go
	// processes avoid thousands of sequential JVM starts on the critical path.
	jobs := make([]func() error, 0, len(patterns))
	for i, pattern := range patterns {
		file := filepath.Join(work, fmt.Sprintf("interop-%d.json", i))
		streams = append(streams, file)
		jobs = append(jobs, func() error {
			return command("proof", "capture", "-out", file, "--", "-tags=interop", "-timeout=15m", "-run="+pattern, "./transform")
		})
	}

	if err := runLanguagePreparationJobs(jobs); err != nil {
		return err
	}

	merge := append([]string{"proof", "merge", "-out", filepath.Join(work, "events.json")}, streams...)
	if err := command(merge...); err != nil {
		return err
	}

	reports := languagePreparedReports(work)

	for i, key := range languageProofProfileKeys() {
		parts := strings.Split(key, "/")

		checkout := inputs.Environment["XMLSEC_QT3_DIR"]
		if parts[0] == suiteXSLT {
			checkout = inputs.Environment["XMLSEC_XSLT_DIR"]
		}

		if explicit := os.Getenv(map[string]string{suiteQT3: "XMLSEC_QT3_DIR", suiteXSLT: "XMLSEC_XSLT_DIR"}[parts[0]]); explicit != "" {
			checkout = explicit
		}
		// Classified publisher failures remain visible in the report and are
		// checked by TestLanguageResidualCoverage, rather than hidden here.
		err := command("suites", "-suite="+parts[0], "-dir="+checkout, "-version="+parts[1], "-xsd-version="+parts[2], "-limits="+parts[3], "-assertions="+parts[4], "-xpath10-compatibility="+parts[5], "-timeout=1s", "-report="+reports[i])

		var report suiteReport
		if readErr := readLanguageProofFile(reports[i], &report); readErr != nil || report.SourceSHA256 != stamp.SourceSHA256 {
			return errors.Join(err, readErr, errors.New("catalog did not produce a current-source report"))
		}
	}

	after, err := currentLanguageProofStamp(ctx, root)
	if err != nil || after != stamp {
		return errors.Join(err, errors.New("sources changed during language preparation; rerun the tests"))
	}

	if err := os.Rename(work, directory); err != nil {
		// Another IDE process may have finished preparing the same snapshot.
		if !languagePreparedValid(directory, stamp) {
			return err
		}
	}

	_, err = fmt.Fprintln(out, "Prepared current language evidence in", directory)

	return err
}

func languageIndependentPatterns(root string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "docs", "conformance.json")) // #nosec G304 -- Fixed repository-relative register.
	if err != nil {
		return nil, err
	}

	var register any
	if err := json.Unmarshal(raw, &register); err != nil {
		return nil, err
	}

	names := make(map[string]struct{})

	var walk func(any)

	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			name, _ := node["name"].(string)
			if node["file"] == "transform/comparison_v1_test.go" && strings.HasPrefix(name, "TestCompare") {
				names[name] = struct{}{}
			}

			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(register)

	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}

	slices.Sort(ordered)

	if len(ordered) == 0 {
		return nil, errors.New("register contains no independent comparison tests")
	}

	groups := make([][]string, min(4, len(ordered)))
	for i, name := range ordered {
		groups[i%len(groups)] = append(groups[i%len(groups)], regexp.QuoteMeta(name))
	}

	patterns := make([]string, len(groups))
	for i, group := range groups {
		patterns[i] = "^(" + strings.Join(group, "|") + ")$"
	}

	return patterns, nil
}

func runLanguagePreparationJobs(jobs []func() error) error {
	results := make(chan error, len(jobs))
	for _, job := range jobs {
		go func() { results <- job() }()
	}

	failures := make([]error, 0, len(jobs))
	for range jobs {
		failures = append(failures, <-results)
	}

	return errors.Join(failures...)
}
