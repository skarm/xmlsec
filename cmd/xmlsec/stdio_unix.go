//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// openLocalFile avoids a blocking open if a path changes to a FIFO before
// the caller can verify the opened descriptor with Stat.
func openLocalFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 G703 -- The operator selects the CLI input path.
}

// Standard descriptors inherited in blocking mode are not necessarily enrolled
// in Go's runtime poller. Closing such an os.File can wait for the blocked read
// itself (notably on macOS). Give streams a pollable owned duplicate, retaining
// the original descriptor and restoring its shared status flags on return.
func prepareFileIO(original *os.File) (*os.File, func(), error) {
	noop := func() {}

	stat, err := original.Stat()
	if err != nil {
		return nil, noop, err
	}

	if stat.Mode().IsRegular() {
		return original, noop, nil
	}

	if err := original.SetDeadline(time.Time{}); err == nil {
		return original, noop, nil
	}

	// The null device completes reads with EOF and accepts writes immediately.
	// It does not require, or on some kernels support, poller registration.
	if stat.Mode()&os.ModeCharDevice != 0 {
		if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(stat, null) {
			return original, noop, nil
		}
	}

	originalFD := original.Fd()

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, originalFD, syscall.F_GETFL, 0)
	if errno != 0 {
		return nil, noop, errno
	}

	fd, err := syscall.Dup(int(originalFD))
	if err != nil {
		return nil, noop, err
	}

	syscall.CloseOnExec(fd)

	restore := func() {
		if flags&syscall.O_NONBLOCK == 0 {
			_ = syscall.SetNonblock(int(originalFD), false)
		}
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, noop, err
	}

	stream := os.NewFile(uintptr(fd), original.Name())

	cleanup := func() { _ = stream.Close(); restore() }
	if err := stream.SetDeadline(time.Time{}); err != nil {
		cleanup()
		return nil, noop, errors.New("input/output stream does not support cancellable I/O")
	}

	return stream, cleanup, nil
}
