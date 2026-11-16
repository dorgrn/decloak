package output

import (
	"encoding/json"
	"io"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/version"
)

type JSONReporter struct {
	w io.Writer
}

type jsonReportEnvelope struct {
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Total    int             `json:"total_findings"`
	Findings []model.Finding `json:"findings"`
}

func (jr *JSONReporter) Write(findings []model.Finding) error {
	if findings == nil {
		findings = []model.Finding{}
	}
	env := jsonReportEnvelope{
		Tool:     "decloak",
		Version:  version.Version,
		Total:    len(findings),
		Findings: findings,
	}
	enc := json.NewEncoder(jr.w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}
