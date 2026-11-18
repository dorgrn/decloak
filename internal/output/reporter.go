package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

// Reporter writes scan findings in a specific output representation.
type Reporter interface {
	Write(findings []model.Finding) error
}

// NewReporter returns a Table, JSON, or SARIF 2.1.0 reporter that identifies
// itself as decloak.
func NewReporter(format string, w io.Writer) (Reporter, error) {
	return NewReporterAs("decloak", format, w)
}

// NewReporterAs is NewReporter with an explicit tool name, for companion
// binaries such as decloak-judge.
func NewReporterAs(tool, format string, w io.Writer) (Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "table":
		return &TableReporter{w: w, color: useColor(w)}, nil
	case "json":
		return &JSONReporter{w: w, tool: tool}, nil
	case "sarif":
		return &SARIFReporter{w: w, tool: tool}, nil
	default:
		return nil, fmt.Errorf("unsupported format %q: expected table, json, or sarif", format)
	}
}
