package rules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

// IgnoreEntry suppresses findings matching an optional rule ID and/or path pattern.
// At least one of RuleID or PathPattern is non-empty.
type IgnoreEntry struct {
	RuleID      string
	PathPattern string
}

// IgnoreFilter filters out findings that match any configured IgnoreEntry.
type IgnoreFilter struct {
	entries []IgnoreEntry
}

// NewIgnoreFilter creates an empty IgnoreFilter.
func NewIgnoreFilter() *IgnoreFilter {
	return &IgnoreFilter{}
}

// AddRule adds a rule-only suppression (matches any file).
func (f *IgnoreFilter) AddRule(ruleID string) {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	if id == "" {
		return
	}
	f.entries = append(f.entries, IgnoreEntry{RuleID: id})
}

// AddEntry adds an IgnoreEntry to the filter.
func (f *IgnoreFilter) AddEntry(e IgnoreEntry) {
	e.RuleID = strings.ToUpper(strings.TrimSpace(e.RuleID))
	e.PathPattern = filepath.ToSlash(strings.TrimSpace(e.PathPattern))
	if e.RuleID == "" && e.PathPattern == "" {
		return
	}
	f.entries = append(f.entries, e)
}

// LoadIgnoreFile reads a .decloakignore file. If optional is true and the file
// does not exist, an empty filter is returned with no error.
func LoadIgnoreFile(path string, optional bool) (*IgnoreFilter, error) {
	file, err := os.Open(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return NewIgnoreFilter(), nil
		}
		return nil, err
	}
	defer func() { _ = file.Close() }()

	filter, err := ParseIgnoreFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return filter, nil
}

// ParseIgnoreFile parses ignore entries from r.
// Supported line formats (blank lines and '#' comments are skipped):
//
//	RULE-ID                 suppress RULE-ID in all files
//	RULE-ID:path/glob       suppress RULE-ID in matching files
//	path/glob               suppress all rules in matching files
func ParseIgnoreFile(r io.Reader) (*IgnoreFilter, error) {
	filter := NewIgnoreFilter()
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow trailing inline comments separated by whitespace + '#'.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		entry, err := parseIgnoreLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		filter.AddEntry(entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return filter, nil
}

func parseIgnoreLine(line string) (IgnoreEntry, error) {
	if ruleID, pat, ok := strings.Cut(line, ":"); ok {
		ruleID = strings.TrimSpace(ruleID)
		pat = strings.TrimSpace(pat)
		if ruleID == "" || pat == "" {
			return IgnoreEntry{}, fmt.Errorf("invalid ignore entry %q: expected RULE-ID:path", line)
		}
		return IgnoreEntry{RuleID: ruleID, PathPattern: pat}, nil
	}
	if looksLikeRuleID(line) {
		return IgnoreEntry{RuleID: line}, nil
	}
	return IgnoreEntry{PathPattern: line}, nil
}

func looksLikeRuleID(s string) bool {
	if strings.ContainsAny(s, "/\\*?") {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}

// Match reports whether finding f is suppressed by any entry.
func (f *IgnoreFilter) Match(finding model.Finding) bool {
	if f == nil || len(f.entries) == 0 {
		return false
	}
	ruleID := strings.ToUpper(finding.RuleID)
	slashPath := filepath.ToSlash(filepath.Clean(finding.FilePath))
	base := filepath.Base(slashPath)

	for _, e := range f.entries {
		if e.RuleID != "" && e.RuleID != ruleID {
			continue
		}
		if e.PathPattern == "" {
			return true
		}
		if matchPath(e.PathPattern, slashPath, base) {
			return true
		}
	}
	return false
}

// Apply returns a new slice containing only findings not suppressed by the filter.
func (f *IgnoreFilter) Apply(findings []model.Finding) []model.Finding {
	if f == nil || len(f.entries) == 0 || len(findings) == 0 {
		return findings
	}
	out := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if !f.Match(finding) {
			out = append(out, finding)
		}
	}
	return out
}

func matchPath(pattern, slashPath, base string) bool {
	pat := filepath.ToSlash(filepath.Clean(pattern))
	if pat == slashPath || pat == base {
		return true
	}
	if ok, _ := filepath.Match(pat, slashPath); ok {
		return true
	}
	if !strings.Contains(pat, "/") {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	// Support suffix matching for relative patterns against absolute paths
	// (e.g., "skills/foo/SKILL.md" matching "/home/user/.claude/skills/foo/SKILL.md").
	if strings.HasSuffix(slashPath, "/"+pat) {
		return true
	}
	return false
}
