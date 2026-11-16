package version

import "testing"

func TestStringOmitsUnknownFields(t *testing.T) {
	v, c, d := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = v, c, d })

	Version, Commit, Date = "v0.3.0", "none", "unknown"
	if got, want := String(), "decloak v0.3.0"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	Commit, Date = "abc1234", "2026-11-15"
	if got, want := String(), "decloak v0.3.0 (commit abc1234, built 2026-11-15)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
