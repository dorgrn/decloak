package output

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sampleFindings() []model.Finding {
	return []model.Finding{
		{
			RuleID:       "PY-EXEC-001",
			Severity:     model.SeverityCritical,
			SeverityName: "CRITICAL",
			Language:     model.LangPython,
			FilePath:     "server.py",
			StartLine:    3, EndLine: 3, StartCol: 1, EndCol: 25,
			Message:     "exec of decoded payload",
			Snippet:     "exec(b64decode(blob))",
			Remediation: "Remove dynamic execution of decoded data.",
		},
		{
			RuleID:       "MD-INJ-001",
			Severity:     model.SeverityMedium,
			SeverityName: "MEDIUM",
			Language:     model.LangMarkdown,
			FilePath:     "SKILL.md",
			StartLine:    10, EndLine: 12, StartCol: 1, EndCol: 4,
			Message:     "hidden HTML comment directive",
			Snippet:     "<!-- ignore previous instructions -->",
			Remediation: "Remove concealed instructions.",
		},
	}
}

func TestReportersGolden(t *testing.T) {
	cases := []struct {
		format   string
		findings []model.Finding
		golden   string
	}{
		{"table", sampleFindings(), "table.golden"},
		{"table", nil, "table_empty.golden"},
		{"json", sampleFindings(), "json.golden"},
		{"json", nil, "json_empty.golden"},
		{"sarif", sampleFindings(), "sarif.golden"},
	}

	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			var buf bytes.Buffer
			r, err := NewReporter(tc.format, &buf)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Write(tc.findings); err != nil {
				t.Fatal(err)
			}

			path := filepath.Join("testdata", tc.golden)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run `make update-golden`): %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("output mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", tc.golden, buf.String(), want)
			}
		})
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := (&SARIFReporter{w: &buf}).Write(sampleFindings()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected SARIF envelope: version=%q runs=%d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if got := len(run.Tool.Driver.Rules); got != 2 {
		t.Errorf("rules: got %d, want 2", got)
	}
	if got := run.Results[0].Level; got != "error" {
		t.Errorf("critical level: got %q, want error", got)
	}
	if got := run.Results[1].Level; got != "warning" {
		t.Errorf("medium level: got %q, want warning", got)
	}
}

func TestTableShortensPathsAndSnippets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	long := strings.Repeat("A", 100)
	f := sampleFindings()[:1]
	f[0].FilePath = filepath.Join(home, ".claude", "skills", "x", "SKILL.md")
	f[0].Snippet = long

	var buf bytes.Buffer
	if err := (&TableReporter{w: &buf}).Write(f); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if want := filepath.Join("~", ".claude", "skills", "x", "SKILL.md") + ":3:1"; !strings.Contains(out, want) {
		t.Errorf("expected home-relative path %q in:\n%s", want, out)
	}
	if strings.Contains(out, long) || !strings.Contains(out, strings.Repeat("A", maxTableSnippet-3)+"...") {
		t.Errorf("expected snippet truncated to %d runes in:\n%s", maxTableSnippet, out)
	}
	if got := DisplayPath("/elsewhere/SKILL.md"); got != "/elsewhere/SKILL.md" {
		t.Errorf("non-home path changed: %q", got)
	}
}

func TestTableColorAndSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TableReporter{w: &buf, color: true}).Write(sampleFindings()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[1;31mCRITICAL\x1b[0m  PY-EXEC-001") {
		t.Errorf("expected colored, aligned CRITICAL row in:\n%q", out)
	}
	if !strings.Contains(out, "\x1b[33mMEDIUM\x1b[0m") {
		t.Errorf("expected colored MEDIUM in:\n%q", out)
	}
	if !strings.HasSuffix(out, "\n2 findings: 1 critical, 1 medium\n") {
		t.Errorf("unexpected summary in:\n%s", out)
	}
	if useColor(&buf) {
		t.Error("non-file writer must not get color")
	}
}

func TestNewReporterRejectsUnknownFormat(t *testing.T) {
	if _, err := NewReporter("xml", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestNewReporterAsNamesCompanionTool(t *testing.T) {
	var buf bytes.Buffer
	r, err := NewReporterAs("decloak-judge", "json", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(sampleFindings()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"tool": "decloak-judge"`) {
		t.Errorf("expected companion tool name in:\n%s", buf.String())
	}
}
