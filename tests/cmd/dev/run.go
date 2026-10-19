package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"
)

func listPackages(ctx context.Context, root, pattern string, stderr io.Writer) ([]goPackage, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-json", pattern) // #nosec G204 -- Package patterns come from fixed repository tasks.
	cmd.Dir, cmd.Stderr = root, stderr

	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}

	var packages []goPackage

	d := json.NewDecoder(bytes.NewReader(data))

	for {
		var p goPackage
		if err := d.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}

		packages = append(packages, p)
	}

	return packages, nil
}

func runExamples(ctx context.Context, root string, args []string, out, stderr io.Writer) error {
	fs := flag.NewFlagSet("examples", flag.ContinueOnError)
	fs.SetOutput(stderr)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if fs.NArg() != 0 {
		return errors.New("unexpected examples arguments")
	}

	packages, err := listPackages(ctx, root, "./examples/...", stderr)
	if err != nil {
		return err
	}

	count := 0

	for _, p := range packages {
		if p.Name != "main" {
			continue
		}

		command := []string{"run", p.ImportPath}
		limit, cancel := context.WithTimeout(ctx, time.Minute)
		err := runGo(limit, root, out, stderr, nil, command...)

		cancel()

		if err != nil {
			return err
		}

		count++
	}

	if count == 0 {
		return errors.New("no executable examples found")
	}

	_, err = fmt.Fprintf(out, "%d examples passed\n", count)

	return err
}

type fuzzTarget struct{ Package, Name string }

func discoverFuzz(ctx context.Context, root, pattern string, stderr io.Writer) ([]fuzzTarget, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-json", "-list="+pattern, "./...") // #nosec G204 -- The Go tool validates the test-name pattern; no shell is involved.
	cmd.Dir, cmd.Stderr = root, stderr

	data, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, fmt.Errorf("list fuzz targets: %w", err)
	}

	var targets []fuzzTarget

	d := json.NewDecoder(bytes.NewReader(data))

	for {
		var event struct{ Action, Package, Output string }
		if err := d.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, err
		}

		if event.Action != "output" {
			continue
		}

		for line := range strings.SplitSeq(event.Output, "\n") {
			if strings.HasPrefix(line, "Fuzz") {
				targets = append(targets, fuzzTarget{Package: event.Package, Name: strings.TrimSpace(line)})
			}
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Package == targets[j].Package {
			return targets[i].Name < targets[j].Name
		}

		return targets[i].Package < targets[j].Package
	})

	if len(targets) == 0 {
		return nil, errors.New("no fuzz targets matched")
	}

	return targets, nil
}

func runFuzz(ctx context.Context, root string, args []string, out, stderr io.Writer) error {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.SetOutput(stderr)
	duration := fs.Duration("time", 5*time.Second, "fuzz budget per target")
	pattern := fs.String("match", ".*", "regular expression for target names")

	list := fs.Bool("list", false, "list selected targets without running tests")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if fs.NArg() != 0 || *duration <= 0 {
		return errors.New("positive fuzz duration required; no positional arguments accepted")
	}

	targets, err := discoverFuzz(ctx, root, *pattern, stderr)
	if err != nil {
		return err
	}

	env := os.Environ()
	for i, e := range slices.Backward(env) {
		if strings.HasPrefix(e, "GOMAXPROCS=") {
			env = append(env[:i], env[i+1:]...)
		}
	}

	env = append(env, "GOMAXPROCS=2")

	for _, target := range targets {
		if *list {
			if _, err := fmt.Fprintf(out, "%s %s\n", target.Package, target.Name); err != nil {
				return err
			}

			continue
		}

		timeout := max(2*time.Minute, *duration+time.Minute)
		if err := runGo(ctx, root, out, stderr, env, "test", target.Package, "-run=^$", "-fuzz=^"+target.Name+"$", "-fuzztime="+duration.String(), "-parallel=2", "-timeout="+timeout.String()); err != nil {
			return err
		}
	}

	if *list {
		_, err = fmt.Fprintf(out, "%d fuzz targets listed\n", len(targets))
	} else {
		_, err = fmt.Fprintf(out, "%d fuzz targets passed\n", len(targets))
	}

	return err
}
