// Package der implements bounded ASN.1 structure handling for offline evidence.
// Indefinite-length BER is deliberately not accepted. Signed attributes must
// additionally pass SetFields, including for implicitly tagged SETs.
package der
