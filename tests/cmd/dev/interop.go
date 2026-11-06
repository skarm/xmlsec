package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// checkInteropLogs makes skipped or incomplete external checks fail the CI gate.
func checkInteropLogs(paths []string, out io.Writer) error {
	if len(paths) == 0 {
		return errors.New("interop-check requires go test -json log files")
	}

	for _, path := range paths {
		file, err := os.Open(path) // #nosec G304 G703 -- Explicit developer-selected local test log.
		if err != nil {
			return err
		}

		count, checkErr := validateInteropLog(file)
		if err = errors.Join(checkErr, file.Close()); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		if _, err = fmt.Fprintf(out, "%s: %d passed tests, zero skips\n", path, count); err != nil {
			return err
		}
	}

	return nil
}

func validateInteropLog(input io.Reader) (int, error) {
	decoder := json.NewDecoder(input)

	var events []languageProofEvent

	passed := 0

	for {
		var event languageProofEvent

		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return 0, err
		}

		if event.Action == goTestSkipEvent {
			return 0, fmt.Errorf("external check skipped: %s/%s", event.Package, event.Test)
		}

		if event.Action == "pass" && event.Test != "" {
			passed++
		}

		events = append(events, event)
	}

	if err := validateLanguageProofPackages(events); err != nil {
		return 0, err
	}

	if passed == 0 {
		return 0, errors.New("no external tests passed")
	}

	return passed, nil
}
