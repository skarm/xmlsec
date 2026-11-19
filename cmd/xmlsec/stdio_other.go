//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import "os"

func openLocalFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 G703 -- The operator selects the CLI input path.
}

func prepareFileIO(file *os.File) (*os.File, func(), error) { return file, func() {}, nil }
