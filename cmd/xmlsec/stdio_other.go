//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import "os"

func prepareFileIO(file *os.File) (*os.File, func(), error) { return file, func() {}, nil }
