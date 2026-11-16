// Package scan scans a single in-memory document. It backs the browser demo,
// which has no filesystem.
package scan

import (
	"encoding/json"
	"sync"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/rules"
	"github.com/dorgrn/decloak/internal/traversal"
)

var (
	once    sync.Once
	engine  *rules.Engine
	initErr error
)

type result struct {
	Findings []model.Finding `json:"findings"`
	Error    string          `json:"error,omitempty"`
}

// JSON scans text as if it were a file named name (the name picks the
// language; unknown names are treated as Markdown) and returns findings as JSON.
func JSON(name, text string) string {
	once.Do(func() {
		reg, err := rules.NewDefaultRegistry()
		if err != nil {
			initErr = err
			return
		}
		engine = rules.NewEngine(reg, rules.EngineConfig{Workers: 1})
	})
	res := result{Findings: []model.Finding{}}
	if initErr != nil {
		res.Error = initErr.Error()
		return marshal(res)
	}
	lang, ok := traversal.ClassifyFile(name)
	if !ok {
		lang = model.LangMarkdown
	}
	findings, err := engine.ScanSource(model.TargetFile{Path: name, Language: lang}, []byte(text))
	if err != nil {
		res.Error = err.Error()
	}
	if findings != nil {
		res.Findings = findings
	}
	return marshal(res)
}

func marshal(r result) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"error":"encode failed"}`
	}
	return string(b)
}
