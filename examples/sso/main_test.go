package main

import (
	"testing"
)

func TestExample(t *testing.T) {
	if e := run(); e != nil {
		t.Fatal(e)
	}
}
