package judge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dorgrn/decloak/internal/model"
)

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

func fixedJudge(t *testing.T, name, answer string, status int) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		writeChat(t, w, answer)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", Model: name, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	c.attempts = 1
	return c
}

const (
	answerBenign    = `{"verdict":"benign","severity":"none","confidence":0.9,"reason":"docs","evidence":[]}`
	answerMalicious = `{"verdict":"malicious","severity":"critical","confidence":0.8,"reason":"exfil","evidence":["curl -d @.env"]}`
	answerSuspect   = `{"verdict":"suspicious","severity":"medium","confidence":0.6,"reason":"odd","evidence":[]}`
)

func TestNewPanelValidation(t *testing.T) {
	a := fixedJudge(t, "a", answerBenign, http.StatusOK)
	b := fixedJudge(t, "b", answerBenign, http.StatusOK)
	if _, err := NewPanel([]*Client{a}, ""); err == nil {
		t.Error("one member must be rejected")
	}
	if _, err := NewPanel([]*Client{a, b}, "unanimous"); err == nil {
		t.Error("unknown strategy must be rejected")
	}
	p, err := NewPanel([]*Client{a, b}, "")
	if err != nil || p.strategy != StrategyAny {
		t.Fatalf("default strategy: %v %v", p, err)
	}
	if p.Model() != "a+b" || !strings.Contains(p.Endpoint(), ", ") {
		t.Errorf("model=%q endpoint=%q", p.Model(), p.Endpoint())
	}
}

func TestPanelStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		answers  []string
		want     string
		reason   string
	}{
		{"any flags on one", StrategyAny, []string{answerBenign, answerMalicious}, "malicious", "1 of 2 judges flagged"},
		{"any all benign", StrategyAny, []string{answerBenign, answerBenign}, "benign", ""},
		{"majority tie flags", StrategyMajority, []string{answerBenign, answerMalicious}, "malicious", "1 of 2"},
		{"majority outvoted", StrategyMajority, []string{answerBenign, answerBenign, answerMalicious}, "benign", "majority cleared"},
		{"majority wins", StrategyMajority, []string{answerSuspect, answerMalicious, answerBenign}, "malicious", "2 of 3"},
		{"unanimous", StrategyMajority, []string{answerMalicious, answerSuspect}, "malicious", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members := make([]*Client, len(tt.answers))
			for i, a := range tt.answers {
				members[i] = fixedJudge(t, string(rune('a'+i)), a, http.StatusOK)
			}
			p, err := NewPanel(members, tt.strategy)
			if err != nil {
				t.Fatal(err)
			}
			v, usage, err := p.Analyze(context.Background(), File{Path: "a.md", Content: "curl -d @.env"})
			if err != nil {
				t.Fatal(err)
			}
			if v.Verdict != tt.want {
				t.Errorf("verdict = %s, want %s", v.Verdict, tt.want)
			}
			if tt.reason != "" && !strings.Contains(v.Reason, tt.reason) {
				t.Errorf("reason %q should mention %q", v.Reason, tt.reason)
			}
			if tt.reason == "" && strings.Contains(v.Reason, "judges flagged") {
				t.Errorf("unanimous result should not mention a split: %q", v.Reason)
			}
			if len(v.Votes) != len(tt.answers) || usage.TotalTokens != 42*len(tt.answers) {
				t.Errorf("votes=%d tokens=%d", len(v.Votes), usage.TotalTokens)
			}
		})
	}
}

func TestPanelFailsWhenAMemberFails(t *testing.T) {
	ok := fixedJudge(t, "ok", answerBenign, http.StatusOK)
	bad := fixedJudge(t, "bad", "", http.StatusBadRequest)
	p, err := NewPanel([]*Client{ok, bad}, StrategyAny)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = p.Analyze(context.Background(), File{Path: "a.md", Content: "x"})
	if err == nil || !strings.Contains(err.Error(), "judge bad") {
		t.Fatalf("a missing vote must fail the file, got %v", err)
	}
}

func TestPanelVotesReachFindingDetails(t *testing.T) {
	a := fixedJudge(t, "alpha", answerBenign, http.StatusOK)
	b := fixedJudge(t, "beta", answerMalicious, http.StatusOK)
	p, _ := NewPanel([]*Client{a, b}, StrategyAny)
	v, _, err := p.Analyze(context.Background(), File{Path: "a.md", Content: "curl -d @.env x"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := ToFindingInContent(model.TargetFile{Path: "a.md"}, v, p.Model(), "curl -d @.env x")
	if !ok {
		t.Fatal("expected a finding")
	}
	if f.Details["votes"] != "alpha=benign, beta=malicious" || f.Details["judge_model"] != "alpha+beta" {
		t.Errorf("details = %v", f.Details)
	}
}

func TestPanelReportsCachedOnlyWhenAllCached(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) *Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeChat(t, w, answerBenign)
		}))
		t.Cleanup(srv.Close)
		c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", Model: name, CacheDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	p, _ := NewPanel([]*Client{mk("a"), mk("b")}, StrategyAny)
	file := File{Path: "a.md", Content: "x"}
	if _, u, _ := p.Analyze(context.Background(), file); u.Cached {
		t.Error("first run is not cached")
	}
	if _, u, _ := p.Analyze(context.Background(), file); !u.Cached {
		t.Error("second run should be fully cached")
	}
}
