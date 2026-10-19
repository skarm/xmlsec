//go:build interop

package interop_test

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	suites := flag.String("suite", "portable", "comma-separated optional suites: portable,xmlsec,all")
	flag.String("xmlsec1", envDefault("XMLSEC1", "xmlsec1"), "external xmlsec1 executable")
	flag.Parse()

	for _, s := range strings.Split(*suites, ",") {
		if s != "portable" && s != "xmlsec" && s != "all" {
			fmt.Fprintln(os.Stderr, "unknown -suite:", s)
			os.Exit(2)
		}
	}

	os.Exit(m.Run())
}

func envDefault(name, fallback string) string {
	if s := os.Getenv(name); s != "" {
		return s
	}

	return fallback
}
