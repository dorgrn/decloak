// Package version holds build metadata injected via -ldflags at release time.
// Builds from `go install module@vX.Y.Z` have no ldflags, so the module
// version and VCS info embedded by the Go toolchain are used instead.
package version

import (
	"runtime/debug"
	"strings"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String formats the version, omitting commit and date when the build did not
// record them (module-proxy builds carry no VCS metadata).
func String() string {
	s := "decloak " + Version
	var extra []string
	if Commit != "none" {
		extra = append(extra, "commit "+Commit)
	}
	if Date != "unknown" {
		extra = append(extra, "built "+Date)
	}
	if len(extra) > 0 {
		s += " (" + strings.Join(extra, ", ") + ")"
	}
	return s
}

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		Version = v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				Commit = s.Value[:7]
			}
		case "vcs.time":
			Date = s.Value
		}
	}
}
