package main

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestBinaryIsOffline guarantees decloak can never send scanned content over
// the network or execute scanned code. ("net" itself is pulled in by pflag for
// IP flag parsing and cannot open connections without these packages.)
// The browser build is checked too: the demo page promises nothing is uploaded.
func TestBinaryIsOffline(t *testing.T) {
	builds := []struct {
		name, pkg string
		env       []string
	}{
		{"cli", ".", nil},
		{"wasm", "../decloak-wasm", []string{"GOOS=js", "GOARCH=wasm"}},
	}
	for _, b := range builds {
		cmd := exec.Command("go", "list", "-deps", b.pkg) //nolint:gosec // G204: package paths are fixed above
		cmd.Env = append(os.Environ(), b.env...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: go list: %v", b.name, err)
		}
		deps := strings.Fields(string(out))
		for _, pkg := range []string{"net/http", "net/rpc", "net/smtp", "crypto/tls", "os/exec", "plugin"} {
			if slices.Contains(deps, pkg) {
				t.Errorf("%s build must stay offline and never execute code, but depends on %s", b.name, pkg)
			}
		}
	}
}
