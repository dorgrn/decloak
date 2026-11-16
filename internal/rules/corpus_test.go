package rules

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/traversal"
)

type corpusManifest struct {
	Cases []corpusCase `json:"cases"`
}

type corpusCase struct {
	Path  string         `json:"path"`
	Rules map[string]int `json:"rules"`
}

// TestLabeledCorpus runs every labeled fixture and computes corpus-level
// precision/recall over rule IDs. The manifest is the source of truth: a benign
// fixture is a case with an empty rules map.
func TestLabeledCorpus(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	raw, err := os.ReadFile(filepath.Join(corpusRoot, "manifest.json"))
	if err != nil {
		t.Fatalf("read corpus manifest: %v", err)
	}

	var manifest corpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse corpus manifest: %v", err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("corpus manifest has no cases")
	}

	registry, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	engine := NewEngine(registry, EngineConfig{Workers: 1})

	var truePositives, falsePositives, falseNegatives int

	for _, tc := range manifest.Cases {
		t.Run(tc.Path, func(t *testing.T) {
			path := filepath.Join(corpusRoot, tc.Path)
			lang, ok := traversal.ClassifyFile(path)
			if !ok {
				t.Errorf("corpus file %s is not classified by the walker", tc.Path)
				return
			}
			if _, err := os.Stat(path); err != nil {
				t.Errorf("corpus file %s: %v", tc.Path, err)
				return
			}

			findings, err := engine.Run(context.Background(), []model.TargetFile{{
				Path:         path,
				Language:     lang,
				SourceOrigin: "corpus",
			}})
			if err != nil {
				t.Errorf("scan %s: %v", tc.Path, err)
				return
			}

			got := make(map[string]int)
			for _, finding := range findings {
				got[finding.RuleID]++
			}

			expected := tc.Rules
			if expected == nil {
				expected = map[string]int{}
			}
			if !maps.Equal(got, expected) {
				t.Errorf("rule counts = %v, want %v", got, expected)
				for _, finding := range findings {
					t.Logf("  %s:%d %s", finding.RuleID, finding.StartLine, finding.Snippet)
				}
			}

			for rule, wantCount := range expected {
				gotCount := got[rule]
				matched := min(gotCount, wantCount)
				truePositives += matched
				falsePositives += gotCount - matched
				falseNegatives += wantCount - matched
			}
			for rule, gotCount := range got {
				if _, expectedRule := expected[rule]; !expectedRule {
					falsePositives += gotCount
				}
			}
		})
	}

	precision := ratio(truePositives, truePositives+falsePositives)
	recall := ratio(truePositives, truePositives+falseNegatives)
	t.Logf("corpus: %d cases, TP=%d FP=%d FN=%d precision=%.3f recall=%.3f",
		len(manifest.Cases), truePositives, falsePositives, falseNegatives, precision, recall)
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}
