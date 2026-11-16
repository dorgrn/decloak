package scan

import (
	"encoding/json"
	"os"
	"testing"
)

func TestJSONScansInMemoryText(t *testing.T) {
	src, err := os.ReadFile("../../testdata/corpus/malicious/readme_demo/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	var got result
	if err := json.Unmarshal([]byte(JSON("SKILL.md", string(src))), &got); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range got.Findings {
		ids[f.RuleID] = true
	}
	// Same rules the CLI reports for this file (README example).
	for _, want := range []string{"DEC-PAY-010", "SH-EXEC-001", "MD-INJ-001", "AGT-HIDE-005", "AGT-SEC-004", "SKL-IMG-007", "SKL-PERM-006"} {
		if !ids[want] {
			t.Errorf("missing %s in %+v", want, ids)
		}
	}

	if err := json.Unmarshal([]byte(JSON("notes.txt", "Run tests before committing.")), &got); err != nil || len(got.Findings) != 0 {
		t.Errorf("clean text: findings=%d err=%v", len(got.Findings), err)
	}
}
