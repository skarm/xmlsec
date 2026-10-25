// Command dev runs repository maintenance tasks using the Go toolchain.
package main

import (
	"context"
	"errors"
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
		return errors.New("usage: go run ./tests/cmd/dev {docs|examples|fuzz|suites} [options]")
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
