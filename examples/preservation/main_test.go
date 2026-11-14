package main

import (
	"bytes"
	"encoding/asn1"
	"testing"
	"time"
)

func TestExample(t *testing.T) {
	if e := run(); e != nil {
		t.Fatal(e)
	}
}

func TestDemoIssueOptionsSequence(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 0, 0, 0, time.UTC)
	policy := asn1.ObjectIdentifier{1, 2, 3, 4, 1}
	rootDER := []byte{0x30, 0x00}
	for _, tc := range []struct {
		name     string
		sequence int64
		wantTime time.Time
	}{
		{name: "first_timestamp", sequence: 1, wantTime: time.Date(2026, time.January, 2, 3, 0, 1, 0, time.UTC)},
		{name: "second_timestamp", sequence: 2, wantTime: time.Date(2026, time.January, 2, 3, 0, 2, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := demoIssueOptions(start, tc.sequence, policy, rootDER)
			if options.SerialNumber == nil || options.SerialNumber.Int64() != tc.sequence {
				t.Errorf("serial=%v, want %d", options.SerialNumber, tc.sequence)
			}
			if !options.GenTime.Equal(tc.wantTime) {
				t.Errorf("generation time=%v, want %v", options.GenTime, tc.wantTime)
			}
			if !options.Policy.Equal(policy) || len(options.ExtraCertificates) != 1 || !bytes.Equal(options.ExtraCertificates[0], rootDER) {
				t.Errorf("policy=%v, extra certificates=%x, want %v and one copy of %x", options.Policy, options.ExtraCertificates, policy, rootDER)
			}
		})
	}
}
