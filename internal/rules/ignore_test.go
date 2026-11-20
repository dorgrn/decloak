package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
)

func TestParseIgnoreFileAndMatch(t *testing.T) {
	input := `
# Global rule suppression
SKL-PERM-006

# Scoped rule suppression
SH-DL-001:docs/install.md # documented installer
POL-PREFLIGHT-002:skills/*.md

# Path-only suppression
testdata/benign.md
`
	f, err := ParseIgnoreFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseIgnoreFile error: %v", err)
	}

	cases := []struct {
		name    string
		finding model.Finding
		want    bool
	}{
		{
			name:    "global rule match",
			finding: model.Finding{RuleID: "SKL-PERM-006", FilePath: "/tmp/any/SKILL.md"},
			want:    true,
		},
		{
			name:    "global rule case-insensitive",
			finding: model.Finding{RuleID: "skl-perm-006", FilePath: "SKILL.md"},
			want:    true,
		},
		{
			name:    "scoped rule suffix match",
			finding: model.Finding{RuleID: "SH-DL-001", FilePath: "/repo/docs/install.md"},
			want:    true,
		},
		{
			name:    "scoped rule different file not suppressed",
			finding: model.Finding{RuleID: "SH-DL-001", FilePath: "/repo/evil/SKILL.md"},
			want:    false,
		},
		{
			name:    "glob rule match",
			finding: model.Finding{RuleID: "POL-PREFLIGHT-002", FilePath: "skills/setup.md"},
			want:    true,
		},
		{
			name:    "path-only match suppresses any rule",
			finding: model.Finding{RuleID: "MD-INJ-001", FilePath: "/work/testdata/benign.md"},
			want:    true,
		},
		{
			name:    "unmatched finding kept",
			finding: model.Finding{RuleID: "AGT-EXF-011", FilePath: "/repo/SKILL.md"},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.Match(tc.finding); got != tc.want {
				t.Fatalf("Match(%+v) = %v, want %v", tc.finding, got, tc.want)
			}
		})
	}
}

func TestParseIgnoreFileInvalidLine(t *testing.T) {
	if _, err := ParseIgnoreFile(strings.NewReader("SKL-PERM-006:")); err == nil {
		t.Fatal("expected error for empty path in RULE:path")
	}
	if _, err := ParseIgnoreFile(strings.NewReader(":SKILL.md")); err == nil {
		t.Fatal("expected error for empty rule in RULE:path")
	}
}

func TestLoadIgnoreFileOptional(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, ".decloakignore")

	f, err := LoadIgnoreFile(missing, true)
	if err != nil {
		t.Fatalf("optional LoadIgnoreFile error: %v", err)
	}
	if f.Match(model.Finding{RuleID: "SKL-PERM-006", FilePath: "SKILL.md"}) {
		t.Fatal("empty optional filter should not match anything")
	}

	if _, err := LoadIgnoreFile(missing, false); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error for required file, got %v", err)
	}
}

func TestIgnoreFilterApply(t *testing.T) {
	f := NewIgnoreFilter()
	f.AddRule("SKL-PERM-006")

	in := []model.Finding{
		{RuleID: "SKL-PERM-006", FilePath: "a.md"},
		{RuleID: "MD-INJ-001", FilePath: "a.md"},
	}
	out := f.Apply(in)
	if len(out) != 1 || out[0].RuleID != "MD-INJ-001" {
		t.Fatalf("unexpected Apply result: %+v", out)
	}
}
