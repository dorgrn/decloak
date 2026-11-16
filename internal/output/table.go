package output

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/dorgrn/decloak/internal/model"
)

type TableReporter struct {
	w     io.Writer
	color bool
}

var severityColor = map[string]string{
	"CRITICAL": "\x1b[1;31m",
	"HIGH":     "\x1b[31m",
	"MEDIUM":   "\x1b[33m",
	"LOW":      "\x1b[36m",
}

const colorReset = "\x1b[0m"

// useColor reports whether w is an interactive terminal and the user has not
// opted out via NO_COLOR (https://no-color.org) or TERM=dumb.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (tr *TableReporter) Write(findings []model.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(tr.w, "No security anomalies detected (0 findings).")
		return err
	}

	// Lay out without escapes (tabwriter counts them as width), then colorize.
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SEVERITY\tRULE ID\tLANGUAGE\tLOCATION\tSNIPPET"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "--------\t-------\t--------\t--------\t-------"); err != nil {
		return err
	}

	for _, f := range findings {
		loc := fmt.Sprintf("%s:%d:%d", DisplayPath(f.FilePath), f.StartLine, f.StartCol)
		snippet := shorten(strings.ReplaceAll(f.Snippet, "\t", " "), maxTableSnippet)
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.SeverityName,
			f.RuleID,
			f.Language,
			loc,
			snippet,
		); err != nil {
			return err
		}
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	out := buf.String()
	if tr.color {
		lines := strings.SplitAfter(out, "\n")
		for i, line := range lines {
			sev, _, _ := strings.Cut(line, " ")
			if c, ok := severityColor[sev]; ok {
				lines[i] = c + sev + colorReset + line[len(sev):]
			}
		}
		out = strings.Join(lines, "")
	}
	if _, err := io.WriteString(tr.w, out); err != nil {
		return err
	}

	_, err := fmt.Fprintf(tr.w, "\n%s\n", summary(findings))
	return err
}

// summary renders e.g. "7 findings: 2 critical, 4 high, 1 medium".
func summary(findings []model.Finding) string {
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var parts []string
	for s := model.SeverityCritical; s >= model.SeverityLow; s-- {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.String())))
		}
	}
	noun := "findings"
	if len(findings) == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("%d %s: %s", len(findings), noun, strings.Join(parts, ", "))
}

// maxTableSnippet keeps table rows readable; JSON and SARIF carry the full snippet.
const maxTableSnippet = 60

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

// DisplayPath abbreviates the user's home directory to "~" for human-readable output.
func DisplayPath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
		return "~" + string(filepath.Separator) + rest
	}
	return p
}
