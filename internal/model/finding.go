package model

import (
	"fmt"
	"strings"
)

// Language identifies the grammar used to parse a target or embedded code block.
type Language string

const (
	LangMarkdown   Language = "markdown"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangTSX        Language = "tsx"
	LangShell      Language = "shell"
	LangPowerShell Language = "powershell"
)

// Severity represents the impact level of a detected finding.
type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) SARIFLevel() string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical, nil
	case "high":
		return SeverityHigh, nil
	case "medium":
		return SeverityMedium, nil
	case "low":
		return SeverityLow, nil
	default:
		return 0, fmt.Errorf("invalid severity %q: expected critical, high, medium, or low", raw)
	}
}

// TargetFile represents a discovered file on disk (either directly walked or
// referenced by an MCP configuration file).
type TargetFile struct {
	Path         string
	Language     Language
	SourceOrigin string // e.g., "walk" or "mcp-config:.cursor/mcp.json#serverName"
}

// CodeBlockSlice represents a fenced code block extracted from a Markdown file,
// preserving the parent file's starting line and byte offset for accurate reporting.
type CodeBlockSlice struct {
	Language       Language
	Content        []byte
	BaseLineOffset uint32 // 0-based line number in parent Markdown where code content starts
}

// Finding categories split concealment findings (content hidden from reviewers)
// from policy findings (visible but dangerous capabilities). They are scored
// separately so enabling policy checks does not dilute the concealment signal.
const (
	CategoryConcealment = "concealment"
	CategoryPolicy      = "policy"
	CategoryJudge       = "judge"
)

// Finding represents a concrete security violation reported by an AST query or
// lexical concealment detector.
type Finding struct {
	Category     string            `json:"category,omitempty"`
	RuleID       string            `json:"rule_id"`
	Severity     Severity          `json:"-"`
	SeverityName string            `json:"severity"`
	Language     Language          `json:"language"`
	FilePath     string            `json:"file_path"`
	SourceOrigin string            `json:"source_origin,omitempty"`
	StartLine    uint32            `json:"start_line"`
	EndLine      uint32            `json:"end_line"`
	StartCol     uint32            `json:"start_col"`
	EndCol       uint32            `json:"end_col"`
	Message      string            `json:"message"`
	Snippet      string            `json:"snippet"`
	Remediation  string            `json:"remediation"`
	Details      map[string]string `json:"details,omitempty"`
}

// ShouldFail returns true if any finding meets or exceeds the configured threshold.
func ShouldFail(findings []Finding, threshold Severity) bool {
	for _, f := range findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}
