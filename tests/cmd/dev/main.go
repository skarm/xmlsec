// Command dev runs repository maintenance tasks using the Go toolchain.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	stop()

	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: go run ./tests/cmd/dev {docs|examples|fuzz|suites|proof} [options]")
	}

	root, err := repositoryRoot()
	if err != nil {
		return err
	}

	switch args[0] {
	case "docs":
		if len(args) != 1 {
			return errors.New("docs does not accept additional arguments")
		}

		return checkDocs(root, out)
	case "examples":
		return runExamples(ctx, root, args[1:], out, stderr)
	case "fuzz":
		return runFuzz(ctx, root, args[1:], out, stderr)
	case "suites":
		return runSuites(ctx, root, args[1:], out, stderr)
	case "proof":
		return runLanguageProof(ctx, root, args[1:], out, stderr)
	default:
		return fmt.Errorf("unknown development command %q", args[0])
	}
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && info.Mode().IsRegular() {
			return filepath.EvalSymlinks(dir)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run the development command from inside the repository")
		}

		dir = parent
	}
}

func runGo(ctx context.Context, root string, out, stderr io.Writer, env []string, args ...string) error {
	if _, err := fmt.Fprintln(out, "$ go "+strings.Join(args, " ")); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- Repository tasks supply Go arguments directly, without a shell.

	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.Env = root, out, stderr, env
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return fmt.Errorf("go %s: %w", args[0], err)
	}

	return nil
}

type goPackage struct {
	ImportPath, Name string
}

type languageProofStamp struct {
	SourceSHA256   string `json:"source_sha256"`
	RegisterSHA256 string `json:"register_sha256"`
}

type languageProofEvent struct {
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Action  string `json:"Action"`
	Output  string `json:"Output,omitempty"`
}

// A capture is stamped around the actual Go process, not when its events are
// later combined with reports from another invocation.
type languageProofStream struct {
	SchemaVersion int                  `json:"schema_version"`
	Before        languageProofStamp   `json:"before"`
	After         languageProofStamp   `json:"after"`
	Arguments     []string             `json:"arguments"`
	ExitCode      int                  `json:"exit_code"`
	DecodeError   string               `json:"decode_error,omitempty"`
	Events        []languageProofEvent `json:"events"`
}

type languageProofArtifact struct {
	SchemaVersion int                   `json:"schema_version"`
	Stamp         languageProofStamp    `json:"stamp"`
	Streams       []languageProofStream `json:"streams"`
}

func languageProofProfileKeys() []string {
	return []string{
		"qt3/2.0/1.0/default/true/false", "qt3/3.0/1.0/default/true/false", "qt3/3.1/1.0/default/true/false",
		"xslt30/2.0/1.0/default/true/false", "xslt30/3.0/1.0/default/true/false",
		"qt3/3.1/1.1/default/true/false", "xslt30/3.0/1.1/default/true/false", "xslt30/3.0/1.0/default/false/false",
		"qt3/2.0/1.0/default/true/true", "qt3/3.0/1.0/default/true/true", "qt3/3.1/1.0/default/true/true",
		"qt3/3.1/1.0/language/true/false", "xslt30/3.0/1.0/language/true/false",
	}
}

func currentLanguageProofStamp(ctx context.Context, root string) (languageProofStamp, error) {
	source, err := suiteSourceDigest(ctx, root)
	if err != nil {
		return languageProofStamp{}, err
	}

	register, err := os.ReadFile(filepath.Join(root, "docs", "conformance.json")) // #nosec G304 -- The developer command selects the local repository root.
	if err != nil {
		return languageProofStamp{}, err
	}

	return languageProofStamp{SourceSHA256: source, RegisterSHA256: fmt.Sprintf("%x", sha256.Sum256(register))}, nil
}

func (s languageProofStream) validate(stamp languageProofStamp) error {
	if s.SchemaVersion != 1 || s.Before != stamp || s.After != stamp {
		return errors.New("test stream has stale or changed source/register stamps")
	}

	if s.ExitCode != 0 || s.DecodeError != "" {
		return fmt.Errorf("test stream process failed with exit code %d", s.ExitCode)
	}

	if len(s.Arguments) < 4 || s.Arguments[0] != "test" || s.Arguments[1] != "-json" || s.Arguments[2] != "-count=1" {
		return errors.New("test stream was not captured by the proof runner")
	}

	return validateLanguageProofPackages(s.Events)
}

func validateLanguageProofPackages(events []languageProofEvent) error {
	started, completed := make(map[string]bool), make(map[string]bool)

	for _, event := range events {
		if event.Action == "fail" || event.Action == "build-fail" {
			return fmt.Errorf("test stream contains %s in %s/%s", event.Action, event.Package, event.Test)
		}

		if event.Test != "" {
			if !started[event.Package] || completed[event.Package] {
				return errors.New("test event lies outside its completed package run")
			}

			continue
		}

		switch event.Action {
		case "start":
			if event.Package == "" || started[event.Package] {
				return errors.New("test stream has an empty or repeated package start")
			}

			started[event.Package] = true
		case "pass", goTestSkipEvent:
			// Go also completes packages containing no test files with skip.
			// Referenced skipped tests remain invalid at the witness gate.
			if !started[event.Package] || completed[event.Package] {
				return errors.New("test stream has an unmatched package completion")
			}

			completed[event.Package] = true
		}
	}

	if len(started) == 0 || len(started) != len(completed) {
		return errors.New("test stream is incomplete: missing package completion")
	}

	return nil
}

func (a languageProofArtifact) validate(stamp languageProofStamp) ([]languageProofEvent, error) {
	if a.SchemaVersion != 1 || a.Stamp != stamp || len(a.Streams) == 0 {
		return nil, errors.New("proof artifact has stale stamps or no captured streams")
	}

	var events []languageProofEvent

	for index, stream := range a.Streams {
		if err := stream.validate(stamp); err != nil {
			return nil, fmt.Errorf("proof stream %d: %w", index+1, err)
		}

		events = append(events, stream.Events...)
	}

	return events, nil
}

func readLanguageProofFile(path string, target any) (readErr error) {
	file, err := os.Open(path) // #nosec G304 G703 -- Explicit developer-supplied proof artifact, not an application resource URI.
	if err != nil {
		return err
	}
	defer func() { readErr = errors.Join(readErr, file.Close()) }()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("proof artifact has trailing JSON")
	}

	return nil
}

func writeLanguageProofFile(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(data, '\n'), 0o600) // #nosec G703 -- Developer-selected temporary evidence artifact, not an application resource URI.
}

const goTestSkipEvent = "skip"

func runLanguageProof(ctx context.Context, root string, args []string, out, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "capture" && args[0] != "merge" {
		return errors.New("usage: proof {capture|merge} -out FILE -- {GO_TEST_ARGUMENTS|CAPTURE_FILES}")
	}

	flags := flag.NewFlagSet("proof "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)

	path := flags.String("out", "", "external proof artifact destination")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	if *path == "" || len(flags.Args()) == 0 {
		return errors.New("proof requires -out FILE and test arguments or capture files")
	}

	if args[0] == "capture" {
		return captureLanguageProof(ctx, root, *path, flags.Args(), out, stderr)
	}

	stamp, err := currentLanguageProofStamp(ctx, root)
	if err != nil {
		return err
	}

	artifact := languageProofArtifact{SchemaVersion: 1, Stamp: stamp}

	for _, file := range flags.Args() {
		absolute, err := filepath.Abs(file)
		if err != nil {
			return err
		}

		destination, err := filepath.Abs(*path)
		if err != nil || absolute == destination {
			return errors.Join(err, errors.New("proof destination must differ from every capture input"))
		}
	}
	// A failed or interrupted merge must not leave a previously valid envelope
	// at the selected destination.
	if err := writeLanguageProofFile(*path, artifact); err != nil {
		return err
	}

	for _, file := range flags.Args() {
		var stream languageProofStream
		if err := readLanguageProofFile(file, &stream); err != nil {
			return fmt.Errorf("capture %s: %w", file, err)
		}

		if err := stream.validate(stamp); err != nil {
			return fmt.Errorf("capture %s: %w", file, err)
		}

		artifact.Streams = append(artifact.Streams, stream)
	}

	after, err := currentLanguageProofStamp(ctx, root)
	if err != nil || after != stamp {
		return errors.Join(err, errors.New("sources or register changed while merging proof captures"))
	}

	if err := writeLanguageProofFile(*path, artifact); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Merged %d source-bound proof captures into %s\n", len(artifact.Streams), *path)

	return err
}

func captureLanguageProof(ctx context.Context, root, path string, args []string, out, stderr io.Writer) error {
	before, err := currentLanguageProofStamp(ctx, root)
	if err != nil {
		return err
	}

	stream := languageProofStream{SchemaVersion: 1, Before: before, Arguments: append([]string{"test", "-json", "-count=1"}, args...), ExitCode: -1}
	if err := writeLanguageProofFile(path, stream); err != nil {
		return err
	}

	commandCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	command := exec.CommandContext(commandCtx, "go", stream.Arguments...) // #nosec G204 -- Explicit developer Go test arguments, without a shell.
	command.Dir, command.Stderr = root, stderr

	pipe, err := command.StdoutPipe()
	if err != nil {
		return err
	}

	if err := command.Start(); err != nil {
		return err
	}

	decoder := json.NewDecoder(pipe)

	var decodeErr error

	for {
		var event languageProofEvent
		if decodeErr = decoder.Decode(&event); decodeErr != nil {
			if decodeErr == io.EOF {
				decodeErr = nil
			} else {
				cancel()
			}

			break
		}

		stream.Events = append(stream.Events, event)
	}

	runErr := command.Wait()

	if decodeErr != nil {
		stream.DecodeError = decodeErr.Error()
	}

	if command.ProcessState != nil {
		stream.ExitCode = command.ProcessState.ExitCode()
	}

	stream.After, err = currentLanguageProofStamp(context.WithoutCancel(ctx), root)
	if err != nil {
		return err
	}

	if err := writeLanguageProofFile(path, stream); err != nil {
		return err
	}

	if err := errors.Join(decodeErr, runErr, stream.validate(before)); err != nil {
		return fmt.Errorf("invalid proof capture saved to %s: %w", path, err)
	}

	_, err = fmt.Fprintf(out, "Captured %d Go test events in %s\n", len(stream.Events), path)

	return err
}
