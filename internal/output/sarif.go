package output

import (
	"encoding/json"
	"io"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/version"
)

type SARIFReporter struct {
	w io.Writer
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   uint32       `json:"startLine"`
	EndLine     uint32       `json:"endLine"`
	StartColumn uint32       `json:"startColumn"`
	EndColumn   uint32       `json:"endColumn"`
	Snippet     sarifMessage `json:"snippet"`
}

func (sr *SARIFReporter) Write(findings []model.Finding) error {
	ruleSeen := make(map[string]struct{})
	var rules []sarifRule
	var results []sarifResult

	for _, f := range findings {
		if _, exists := ruleSeen[f.RuleID]; !exists {
			ruleSeen[f.RuleID] = struct{}{}
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				ShortDescription: sarifMessage{Text: f.Message},
				Help:             sarifMessage{Text: f.Remediation},
			})
		}

		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   f.Severity.SARIFLevel(),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: f.FilePath},
						Region: sarifRegion{
							StartLine:   f.StartLine,
							EndLine:     f.EndLine,
							StartColumn: f.StartCol,
							EndColumn:   f.EndCol,
							Snippet:     sarifMessage{Text: f.Snippet},
						},
					},
				},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "decloak",
						InformationURI: "https://github.com/dorgrn/decloak",
						Version:        version.Version,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(sr.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
