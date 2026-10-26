package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestCLIProcessHelper(_ *testing.T) {
	if os.Getenv("XMLSEC_PROCESS_TEST") != "1" {
		return
	}

	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("XMLSEC_PROCESS_ARGS")), &args); err != nil {
		os.Exit(99)
	}

	os.Args = append([]string{"xmlsec"}, args...)

	main()
	os.Exit(0)
}

func TestProcessInterruptsBlockedStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt is not supported by os.Process.Signal on Windows")
	}

	cmd := testProcess(t, nameC14n)

	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	var stderr bytes.Buffer

	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// More than the OS pipe buffer: completion proves main installed its signal
	// handler and entered readInputContext. No timing-based startup assumption.
	if _, err := input.Write(append([]byte("<r>"), bytes.Repeat([]byte{'x'}, 2<<20)...)); err != nil {
		_ = cmd.Wait()

		t.Fatal(err, stderr.String())
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Wait()

		t.Fatal(err)
	}

	err = cmd.Wait()

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Fatal("interrupt did not cancel blocked stdin", err, stderr.String())
	}
}

func TestProcessJSONErrorsAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{{[]string{jsonErrorsFlag, nameUnknown}, 2}, {[]string{jsonErrorsFlag, nameC14n, "-timeout", "25ms"}, 124}, {[]string{jsonErrorsFlag, nameC14n, "-bad-flag"}, 2}} {
		cmd := testProcess(t, tc.args...)

		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}

		var stderr bytes.Buffer

		cmd.Stderr = &stderr
		err = cmd.Run()
		_ = input.Close()

		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != tc.code {
			t.Fatal(tc.args, err, stderr.String())
		}

		if !json.Valid(stderr.Bytes()) {
			t.Fatal("non-JSON diagnostics", stderr.String())
		}
	}
}

func TestProcessInterruptsBlockedStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt is not supported by os.Process.Signal on Windows")
	}

	cmd := testProcess(t, nameC14n)
	cmd.Stdin = bytes.NewReader(append(append([]byte("<r>"), bytes.Repeat([]byte{'x'}, 2<<20)...), []byte("</r>")...))

	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	var stderr bytes.Buffer

	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	one := make([]byte, 1)
	if _, err := output.Read(one); err != nil {
		_ = cmd.Wait()

		t.Fatal(err, stderr.String())
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Wait()

		t.Fatal(err)
	}

	err = cmd.Wait()

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Fatal("interrupt did not cancel blocked stdout", err, stderr.String())
	}
}

func testProcess(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()

	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)

	raw, err := json.Marshal(args)
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestCLIProcessHelper$")

	cmd.Env = append(os.Environ(), "XMLSEC_PROCESS_TEST=1", "XMLSEC_PROCESS_ARGS="+string(raw))

	t.Cleanup(cancel)

	return cmd
}
