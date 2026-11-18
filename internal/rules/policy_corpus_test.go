package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/traversal"
)

// TestPolicyCorpus exercises the opt-in policy stream against labeled fixtures.
// Only POL-* findings are asserted; concealment findings from the same input
// are covered by TestLabeledCorpus and are out of scope here.
func TestPolicyCorpus(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "testdata", "corpus")
	raw, err := os.ReadFile(filepath.Join(corpusRoot, "policy_manifest.json"))
	if err != nil {
		t.Fatalf("read policy corpus manifest: %v", err)
	}

	var manifest corpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse policy corpus manifest: %v", err)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("policy corpus manifest has no cases")
	}

	registry, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("NewDefaultRegistry: %v", err)
	}
	engine := NewEngine(registry, EngineConfig{Workers: 1, Policy: true})

	for _, tc := range manifest.Cases {
		t.Run(tc.Path, func(t *testing.T) {
			path := filepath.Join(corpusRoot, tc.Path)
			lang, ok := traversal.ClassifyFile(path)
			if !ok {
				t.Errorf("corpus file %s is not classified by the walker", tc.Path)
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
				if strings.HasPrefix(finding.RuleID, "POL-") {
					got[finding.RuleID]++
				}
			}

			expected := tc.Rules
			if expected == nil {
				expected = map[string]int{}
			}
			if len(got) != len(expected) {
				t.Errorf("policy rules = %v, want %v", got, expected)
				return
			}
			for rule, count := range expected {
				if got[rule] != count {
					t.Errorf("rule %s: got %d, want %d (all: %v)", rule, got[rule], count, got)
				}
			}
		})
	}
}
