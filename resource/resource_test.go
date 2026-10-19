package resource_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"testing"

	"github.com/skarm/xmlsec/resource"
)

const fsBaseURI = "embed:/"

func TestFSResolverRejectsNilFiles(t *testing.T) {
	var typedNil *testFile
	for _, file := range []fs.File{nil, typedNil} {
		resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { return file, nil })})
		if err != nil {
			t.Fatal(err)
		}

		stream, err := resolver.Resolve(t.Context(), "embed:/file")
		if stream != nil || !errors.Is(err, resource.ErrResource) {
			t.Fatal(stream, err)
		}
	}
}

func TestFSResolverClosesFileReturnedWithError(t *testing.T) {
	openErr, closeErr := errors.New("open failed"), errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { return file, openErr })})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(t.Context(), "embed:/file")
	if stream != nil || !errors.Is(err, resource.ErrResource) || !errors.Is(err, openErr) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestFSResolverClosesAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	closeErr := errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: openFunc(func(string) (fs.File, error) { cancel(); return file, nil })})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(ctx, "embed:/file")
	if stream != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestHTTPStatusFailureClosesBodyAndPreservesCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	file := &testFile{closeErr: closeErr}

	resolver, err := resource.NewHTTPResolver(resource.HTTPConfig{AllowedOrigins: []string{"https://resource.test"}, Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: file, Header: make(http.Header), Request: req}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}

	stream, err := resolver.Resolve(t.Context(), "https://resource.test/missing")
	if stream != nil || !errors.Is(err, resource.ErrResource) || !errors.Is(err, closeErr) || file.closes != 1 {
		t.Fatal(stream, err, file.closes)
	}
}

func TestFSResolverRejectsTypedNilFilesystem(t *testing.T) {
	var filesystem openFunc
	if resolver, err := resource.NewFSResolver(resource.FSConfig{BaseURI: fsBaseURI, FS: filesystem}); resolver != nil || !errors.Is(err, resource.ErrInput) {
		t.Fatal(resolver, err)
	}
}

func TestHTTPResolverCancellationAtOpenAndFinalRead(t *testing.T) {
	for _, duringOpen := range []bool{false, true} {
		t.Run(strconv.FormatBool(duringOpen), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			closes := 0
			body := &callbackBody{read: func(p []byte) (int, error) {
				cancel()
				return copy(p, "complete"), io.EOF
			}, close: func() error { closes++; return nil }}

			resolver, err := resource.NewHTTPResolver(resource.HTTPConfig{AllowedOrigins: []string{"https://resource.test"}, Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if duringOpen {
					cancel()
				}

				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header), Request: req}, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}

			reader, err := resolver.Resolve(ctx, "https://resource.test/value")
			if duringOpen {
				if reader != nil || !errors.Is(err, context.Canceled) || closes != 1 {
					t.Fatal(reader, err, closes)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			data, err := io.ReadAll(reader)

			closeErr := reader.Close()
			if string(data) != "complete" || !errors.Is(err, context.Canceled) || closeErr != nil || closes != 1 {
				t.Fatal(string(data), err, closeErr, closes)
			}
		})
	}
}

type openFunc func(string) (fs.File, error)

func (f openFunc) Open(name string) (fs.File, error) { return f(name) }

type testFile struct {
	closes   int
	closeErr error
}

func (f *testFile) Read([]byte) (int, error) { panic("unexpected read") }

func (f *testFile) Stat() (fs.FileInfo, error) { panic("unexpected stat") }

func (f *testFile) Close() error { f.closes++; return f.closeErr }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type callbackBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (r *callbackBody) Read(p []byte) (int, error) { return r.read(p) }

func (r *callbackBody) Close() error { return r.close() }
