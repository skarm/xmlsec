//go:build interop

package transform_test

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

//go:embed testdata/SaxonWorker.java
var saxonWorkerSource string

var saxonWorkerPools sync.Map //nolint:gochecknoglobals // Each pool belongs to one top-level comparison and is removed by its cleanup.

type saxonWorkerPool struct {
	slots  chan struct{}
	idle   chan *saxonWorker
	source string
}

type saxonWorker struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	input  io.WriteCloser
	output *bufio.Reader
	stderr bytes.Buffer
}

type saxonWorkerError struct {
	status int
	stderr []byte
}

func (e *saxonWorkerError) Error() string {
	return fmt.Sprintf("Saxon exit status %d: %s", e.status, e.stderr)
}

func saxonPoolKey(t *testing.T, binary, classpath string) string {
	t.Helper()
	return strings.SplitN(t.Name(), "/", 2)[0] + "\x00" + binary + "\x00" + classpath
}

func prepareSaxonWorkers(t *testing.T, binary, classpath string) {
	t.Helper()
	if os.Getenv("XMLSEC_SAXON_PROCESS") == "1" || saxonProofOracle(t, binary, classpath) != "saxon-12.10" {
		return
	}
	key := saxonPoolKey(t, binary, classpath)
	parallel, err := strconv.Atoi(flag.Lookup("test.parallel").Value.String())
	if err != nil || parallel < 1 {
		t.Fatal("invalid test parallelism", parallel, err)
	}
	pool := &saxonWorkerPool{
		slots:  make(chan struct{}, parallel),
		idle:   make(chan *saxonWorker, parallel),
		source: filepath.Join(t.TempDir(), "SaxonWorker.java"),
	}
	if err := os.WriteFile(pool.source, []byte(saxonWorkerSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, loaded := saxonWorkerPools.LoadOrStore(key, pool); loaded {
		return
	}
	t.Cleanup(func() {
		saxonWorkerPools.Delete(key)
		for len(pool.idle) > 0 {
			(<-pool.idle).stop()
		}
	})
}

func startSaxonWorker(binary, classpath, source string) (*saxonWorker, error) {
	ctx, cancel := context.WithCancel(context.Background())
	worker := &saxonWorker{cmd: exec.CommandContext(ctx, binary, "-cp", classpath, source), cancel: cancel}
	worker.cmd.Stderr = &worker.stderr
	worker.cmd.WaitDelay = 5 * time.Second
	var err error
	worker.input, err = worker.cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := worker.cmd.StdoutPipe()
	if err != nil {
		worker.input.Close()
		cancel()
		return nil, err
	}
	worker.output = bufio.NewReader(stdout)
	if err := worker.cmd.Start(); err != nil {
		worker.input.Close()
		stdout.Close()
		cancel()
		return nil, err
	}
	return worker, nil
}

func (w *saxonWorker) stop() {
	w.cancel()
	w.input.Close()
	w.cmd.Wait()
}

func (w *saxonWorker) exchange(mode string, args []string) ([]byte, error) {
	var request strings.Builder
	request.WriteString(mode)
	for _, arg := range args {
		request.WriteByte('\t')
		request.WriteString(base64.StdEncoding.EncodeToString([]byte(arg)))
	}
	request.WriteByte('\n')
	if _, err := io.WriteString(w.input, request.String()); err != nil {
		return nil, err
	}
	line, err := w.output.ReadString('\n')
	if err != nil {
		return nil, err
	}
	fields := strings.Split(strings.TrimSuffix(line, "\n"), "\t")
	if len(fields) != 3 {
		return nil, fmt.Errorf("invalid Saxon response: %q", line)
	}
	status, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, err
	}
	stdout, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, err
	}
	stderr, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return stdout, &saxonWorkerError{status: status, stderr: stderr}
	}
	return stdout, nil
}

func saxonOutput(t *testing.T, ctx context.Context, binary, classpath, mode string, args ...string) ([]byte, error) {
	t.Helper()
	entry, found := saxonWorkerPools.Load(saxonPoolKey(t, binary, classpath))
	if !found {
		params := append([]string{"-cp", classpath, "net.sf.saxon." + mode}, args...)
		output, err := exec.CommandContext(ctx, binary, params...).Output()
		if ctx.Err() != nil {
			return output, ctx.Err()
		}
		return output, err
	}
	pool := entry.(*saxonWorkerPool)
	select {
	case pool.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var worker *saxonWorker
	defer func() {
		if worker != nil {
			pool.idle <- worker
		}
		<-pool.slots
	}()
	select {
	case worker = <-pool.idle:
	default:
	}
	if worker == nil {
		var err error
		worker, err = startSaxonWorker(binary, classpath, pool.source)
		if err != nil {
			return nil, err
		}
	}
	type response struct {
		output []byte
		err    error
	}
	ready := make(chan response, 1)
	go func() {
		output, err := worker.exchange(mode, args)
		ready <- response{output, err}
	}()
	select {
	case result := <-ready:
		var failure *saxonWorkerError
		if result.err != nil && !errors.As(result.err, &failure) {
			worker.stop()
			result.err = fmt.Errorf("Saxon worker: %w: %s", result.err, worker.stderr.String())
			worker = nil
		}
		return result.output, result.err
	case <-ctx.Done():
		worker.stop()
		<-ready
		worker = nil
		return nil, ctx.Err()
	}
}

func saxonFailureStderr(err error) ([]byte, bool) {
	var worker *saxonWorkerError
	if errors.As(err, &worker) {
		return worker.stderr, true
	}
	var process *exec.ExitError
	if errors.As(err, &process) {
		return process.Stderr, true
	}
	return nil, false
}

func TestCompareSaxonWorkerContracts(t *testing.T) {
	classpath, binary := saxonRuntime(t)
	for _, test := range []struct {
		name    string
		query   string
		options []string
	}{
		{"unicode and framing", `string-join(('café 中',codepoints-to-string((9,10))),'')`, nil},
		{"static error", `1 +`, nil},
		{"recovery after error", `42`, nil},
		{"serialization option", `(1,2,3)`, []string{"!item-separator=|"}},
		{"fresh serialization options", `(1,2,3)`, nil},
		{"dynamic error", `error()`, nil},
		{"large response", `string-join(for $i in 1 to 100000 return 'x','')`, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "query.xq")
			if err := os.WriteFile(file, []byte(test.query), 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"-q:" + file, "!method=text"}, test.options...)
			pooled, pooledErr := saxonOutput(t, t.Context(), binary, classpath, "Query", args...)
			params := append([]string{"-cp", classpath, "net.sf.saxon.Query"}, args...)
			separate, separateErr := exec.CommandContext(t.Context(), binary, params...).Output()
			pooledDiagnostic, pooledFailed := saxonFailureStderr(pooledErr)
			separateDiagnostic, separateFailed := saxonFailureStderr(separateErr)
			if !bytes.Equal(pooled, separate) || (pooledErr == nil) != (separateErr == nil) || pooledFailed != separateFailed || !bytes.Equal(pooledDiagnostic, separateDiagnostic) {
				t.Fatalf("worker: %q, %v, %s; separate process: %q, %v, %s", pooled, pooledErr, pooledDiagnostic, separate, separateErr, separateDiagnostic)
			}
			if pooledErr != nil && !pooledFailed {
				t.Fatal("oracle transport failed", pooledErr)
			}
		})
	}
	t.Run("fresh static serializer tables", func(t *testing.T) {
		for _, version := range []string{"5", "4.01", "5", "4.01"} {
			file := filepath.Join(t.TempDir(), "serialize.xsl")
			source := sheetStart + version30 + `"><xsl:output method="html" version="` + version + `"/><xsl:template name="start"><r><source/><track/><wbr/><keygen/></r></xsl:template></xsl:stylesheet>`
			if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-xsl:" + file, "-it:start"}
			pooled, pooledErr := saxonOutput(t, t.Context(), binary, classpath, "Transform", args...)
			params := append([]string{"-cp", classpath, "net.sf.saxon.Transform"}, args...)
			separate, separateErr := exec.CommandContext(t.Context(), binary, params...).Output()
			if pooledErr != nil || separateErr != nil || !bytes.Equal(pooled, separate) {
				t.Fatalf("HTML%s serializer state leaked: worker=%q (%v), separate=%q (%v)", version, pooled, pooledErr, separate, separateErr)
			}
		}
	})
	t.Run("parallel request isolation", func(t *testing.T) {
		for i := range 8 {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()
				want := fmt.Sprintf("request-%d", i)
				output, err := saxonQuery(t, t.Context(), binary, classpath, "'"+want+"'")
				if err != nil || string(output) != want {
					t.Fatal("response belongs to another request", string(output), err, want)
				}
			})
		}
	})
	t.Run("fresh document pool", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "value.xml")
		for _, want := range []string{"first", "second", "third", "fourth"} {
			if err := os.WriteFile(file, []byte("<r>"+want+"</r>"), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := saxonQuery(t, t.Context(), binary, classpath, "string(doc('"+file+"')/r)")
			if err != nil || string(output) != want {
				t.Fatalf("stale document: %q, %v; want %q", output, err, want)
			}
		}
	})
	t.Run("cancellation and replacement", func(t *testing.T) {
		requested := make(chan struct{}, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested <- struct{}{}
			<-r.Context().Done()
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		file := filepath.Join(t.TempDir(), "query.xq")
		if err := os.WriteFile(file, []byte("doc('"+server.URL+"')"), 0o600); err != nil {
			t.Fatal(err)
		}
		completed := make(chan error, 1)
		go func() {
			_, err := saxonOutput(t, ctx, binary, classpath, "Query", "-q:"+file)
			completed <- err
		}()
		select {
		case <-requested:
			cancel()
		case err := <-completed:
			t.Fatal("oracle exited before the blocking request", err)
		case <-ctx.Done():
			t.Fatal("oracle did not request the blocking document", ctx.Err())
		}
		if err := <-completed; !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation did not terminate the request", err)
		}
		output, err := saxonQuery(t, t.Context(), binary, classpath, "'recovered'")
		if err != nil || string(output) != "recovered" {
			t.Fatal("oracle did not recover after cancellation", string(output), err)
		}
	})
}
