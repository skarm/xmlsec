// Derived from lestrrat-go/helium at 7362c0a70122a757780f4d0b545a9b370dead6ab.
// Copyright (c) 2015 lestrrat. MIT License; see licenses/MIT-helium.txt at the repository root.

package xslt

import (
	"github.com/skarm/xmlsec/transform/internal/xdm"
)

// Parameters holds named XSLT parameter bindings keyed by expanded name
// string (Q{uri}local form). It is a mutable collection: callers build it
// up, then pass it to a Compiler or Invocation. The receiver clones it at
// terminal method time.
type Parameters struct {
	values map[string]xdm.Sequence
}

// NewParameters creates an empty Parameters collection.
func NewParameters() *Parameters {
	return &Parameters{}
}

// Set binds a parameter name to a Sequence value.
func (p *Parameters) Set(name string, value xdm.Sequence) {
	if p.values == nil {
		p.values = make(map[string]xdm.Sequence)
	}

	p.values[name] = value
}

// SetString binds a parameter to a single xs:string value.
func (p *Parameters) SetString(name, value string) {
	p.Set(name, xdm.SingleString(value))
}

// SetAtomic binds a parameter to a single atomic value.
func (p *Parameters) SetAtomic(name string, value xdm.AtomicValue) {
	p.Set(name, xdm.SingleAtomic(value))
}

// Get returns the Sequence bound to name, or false if unbound.
func (p *Parameters) Get(name string) (xdm.Sequence, bool) {
	if p.values == nil {
		return nil, false
	}

	seq, ok := p.values[name]

	return seq, ok
}

// Delete removes a parameter binding.
func (p *Parameters) Delete(name string) {
	delete(p.values, name)
}

// Clear removes all parameter bindings.
func (p *Parameters) Clear() {
	clear(p.values)
}

// Len returns the number of parameter bindings.
func (p *Parameters) Len() int {
	return len(p.values)
}

// Clone returns a deep copy of the Parameters.
func (p *Parameters) Clone() *Parameters {
	if p == nil {
		return nil
	}

	cloned := &Parameters{}
	if p.values != nil {
		cloned.values = make(map[string]xdm.Sequence, len(p.values))
		for name, seq := range p.values {
			cloned.values[name] = xdm.CloneSequence(seq)
		}
	}

	return cloned
}

func (p *Parameters) toMap() map[string]xdm.Sequence {
	if p == nil {
		return nil
	}

	return p.values
}
