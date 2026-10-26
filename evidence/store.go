package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/skarm/xmlsec/internal/nilcheck"
	"github.com/skarm/xmlsec/internal/streamio"
)

// Store retains untrusted observation bytes in a private temporary directory and
// keeps their metadata in memory. Construct it with NewStore and call Close when
// finished. It supports concurrent calls. The application owns the parent directory
// and available disk capacity. Open readers remain caller-owned and must be closed
// before releasing storage. Reading a Record does not authenticate its contents.
type Store struct {
	mutex     sync.Mutex
	directory string
	maximum   int64
	used      int64
	records   int
	closed    bool
}

// NewStore creates a private child directory in directory (empty uses the OS
// temporary directory). maximum bounds committed plus reserved input bytes and
// must be 1..64 MiB. At most 64 records, including active writes, may coexist.
func NewStore(directory string, maximum int64) (*Store, error) {
	if maximum < 1 || maximum > 64<<20 {
		return nil, ErrLimit
	}

	root, err := os.MkdirTemp(directory, "xmlsec-evidence-")
	if err != nil {
		return nil, errors.Join(ErrResource, err)
	}

	return &Store{directory: root, maximum: maximum}, nil
}

// PutReader copies and hashes a bounded input into a private file. maximum must
// be 1..64 MiB and is reserved until EOF, then reduced to the actual size. A
// concurrent write may therefore fail its reservation before the disk is full.
// It leaves src open. Blocking sources must implement context cancellation.
// No record is returned on read/write/close error, cancellation, empty input or limit.
// A failed file cleanup closes the store; Close must retry releasing its files.
func (s *Store) PutReader(ctx context.Context, kind Kind, src io.Reader, provenance Provenance, maximum int) (*Record, error) {
	if s == nil || ctx == nil || !ValidKind(kind) || nilcheck.IsNil(src) {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if maximum < 1 || maximum > 64<<20 {
		return nil, ErrLimit
	}

	provenance, err := snapshotProvenance(provenance)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()

	if s.closed {
		s.mutex.Unlock()
		return nil, errors.Join(ErrResource, os.ErrClosed)
	}

	if s.records >= 64 || int64(maximum) > s.maximum-s.used {
		s.mutex.Unlock()
		return nil, ErrLimit
	}

	f, err := os.CreateTemp(s.directory, "observation-")
	if err != nil {
		s.mutex.Unlock()
		return nil, errors.Join(ErrResource, err)
	}

	s.used += int64(maximum)
	s.records++
	s.mutex.Unlock()

	digest := sha256.New()
	reader := &streamio.Reader{Context: ctx, Source: src, Limit: int64(maximum), LimitError: ErrLimit}

	size, err := reader.WriteTo(io.MultiWriter(f, digest))

	err = errors.Join(err, f.Close(), ctx.Err())
	if err == nil && size == 0 {
		err = ErrInput
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	err = errors.Join(err, ctx.Err())
	if s.closed {
		err = errors.Join(err, ErrResource, os.ErrClosed)
	}

	if err != nil {
		removeErr := os.Remove(f.Name())
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}

		if removeErr == nil {
			s.used -= int64(maximum)
			s.records--
		} else {
			// A failed cleanup must not release budget while the file still exists.
			// Stop new acquisitions; Close can retry removing the private directory.
			s.closed = true
		}

		return nil, errors.Join(err, removeErr)
	}

	s.used -= int64(maximum) - size
	record := &Record{store: s, path: f.Name(), size: int(size), kind: kind, provenance: provenance}
	copy(record.digest[:], digest.Sum(nil))

	return record, nil
}

// Close removes all files and prevents further writes and opens. Existing open
// readers must still be closed by their owners. It is safe to call repeatedly.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.closed = true

	if err := os.RemoveAll(s.directory); err != nil {
		return errors.Join(ErrResource, err)
	}

	return nil
}

// Record identifies exact untrusted bytes retained by a Store. Its immutable
// metadata remains available after closure. Closing the record releases its file
// and storage reservation; repeated Close calls are safe. Open fails after the
// record or its store has closed.
type Record struct {
	store      *Store
	path       string
	size       int
	kind       Kind
	digest     [32]byte
	provenance Provenance
	closed     bool // protected by store.mutex
}

// Open returns a new independently positioned reader over the original bytes.
// The reader checks ctx before and after reads; it remains owned by the caller,
// including after Record.Close or Store.Close. The private files are not exposed
// for mutation by this API. Filesystem/directory integrity is application-owned.
func (r *Record) Open(ctx context.Context) (io.ReadCloser, error) {
	if r == nil || r.store == nil || ctx == nil {
		return nil, ErrInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r.store.mutex.Lock()
	defer r.store.mutex.Unlock()

	if r.closed || r.store.closed {
		return nil, errors.Join(ErrResource, os.ErrClosed)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	file, err := os.Open(filepath.Clean(r.path))
	if err != nil {
		return nil, errors.Join(ErrResource, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, file.Close())
	}

	return &recordReader{Closer: file, reader: streamio.Reader{Context: ctx, Source: file, Limit: int64(r.size), LimitError: ErrLimit}}, nil
}

// Close releases a stored record. It does not close already opened readers.
func (r *Record) Close() error {
	if r == nil || r.store == nil {
		return nil
	}

	r.store.mutex.Lock()
	defer r.store.mutex.Unlock()

	if r.closed {
		return nil
	}

	err := os.Remove(r.path)
	if r.store.closed && errors.Is(err, os.ErrNotExist) {
		err = nil
	}

	if err != nil {
		return errors.Join(ErrResource, err)
	}

	r.closed = true
	r.store.used -= int64(r.size)
	r.store.records--

	return nil
}

// Size returns the exact byte count without reading the stored object.
func (r *Record) Size() int {
	if r == nil {
		return 0
	}

	return r.size
}

// Kind returns the intended offline parser without asserting valid content.
func (r *Record) Kind() Kind {
	if r == nil {
		return ""
	}

	return r.kind
}

// DigestSHA256 returns the digest computed over the exact received bytes.
func (r *Record) DigestSHA256() [32]byte {
	if r == nil {
		return [32]byte{}
	}

	return r.digest
}

// FingerprintSHA256 returns the received byte digest in lowercase hexadecimal.
func (r *Record) FingerprintSHA256() string {
	if r == nil {
		return ""
	}

	return hex.EncodeToString(r.digest[:])
}

// Provenance returns an owned copy of untrusted transport metadata.
func (r *Record) Provenance() Provenance {
	if r == nil {
		return Provenance{}
	}

	p := r.provenance
	p.Redirects = append([]string(nil), p.Redirects...)

	return p
}

type recordReader struct {
	io.Closer
	reader streamio.Reader
}

func (r *recordReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)

	if canceled := r.reader.Context.Err(); canceled != nil {
		return n, errors.Join(err, canceled)
	}

	return n, err
}
