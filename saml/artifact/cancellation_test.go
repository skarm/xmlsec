package artifact_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skarm/xmlsec/document"
	"github.com/skarm/xmlsec/internal/testutil/testcert"
	"github.com/skarm/xmlsec/saml/artifact"
	"github.com/skarm/xmlsec/saml/binding"
)

type observedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *observedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestCancellationWhileWaitingForArtifactTransaction(t *testing.T) {
	for _, operation := range []string{"Put", "Take", "Resolve"} {
		t.Run(operation, func(t *testing.T) {
			at := testcert.Now()
			doc, err := document.Parse(t.Context(), []byte(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"/>`), document.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			store, err := artifact.NewMemoryStore(10)
			if err != nil {
				t.Fatal(err)
			}
			held := binding.Artifact{MessageHandle: [20]byte{1}}
			target := binding.Artifact{MessageHandle: [20]byte{2}}
			added := binding.Artifact{MessageHandle: [20]byte{3}}
			entry := func(a binding.Artifact) artifact.Entry {
				return artifact.Entry{Artifact: a, Recipient: "https://sp.test/entity", Message: doc, ExpiresAt: at.Add(time.Minute)}
			}
			for _, a := range []binding.Artifact{held, target} {
				if err := store.Put(t.Context(), entry(a), at); err != nil {
					t.Fatal(err)
				}
			}
			entered, release, holderDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				_, err := store.Resolve(t.Context(), held, entry(held).Recipient, at, func(message *document.Document) (*document.Document, error) {
					close(entered)
					<-release
					return message, nil
				})
				holderDone <- err
			}()
			<-entered
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			observed := &observedContext{Context: ctx, checked: make(chan struct{})}
			finished := make(chan error, 1)
			var callbacks atomic.Int32
			go func() {
				var err error
				switch operation {
				case "Put":
					err = store.Put(observed, entry(added), at)
				case "Take":
					_, err = store.Take(observed, target, entry(target).Recipient, at)
				case "Resolve":
					_, err = store.Resolve(observed, target, entry(target).Recipient, at, func(message *document.Document) (*document.Document, error) {
						callbacks.Add(1)
						return message, nil
					})
				}
				finished <- err
			}()
			<-observed.checked
			cancel()
			close(release)
			if err := <-holderDone; err != nil {
				t.Fatal(err)
			}
			if err := <-finished; !errors.Is(err, context.Canceled) {
				t.Error("queued canceled operation succeeded", err)
			}
			if callbacks.Load() != 0 {
				t.Error("canceled resolution invoked the signing callback")
			}
			if message, err := store.Take(t.Context(), target, entry(target).Recipient, at); err != nil || message != doc {
				t.Error("canceled operation consumed the artifact", err)
			}
			if message, err := store.Take(t.Context(), added, entry(added).Recipient, at); err != nil || message != nil {
				t.Error("canceled operation inserted an artifact", err)
			}
		})
	}
}
