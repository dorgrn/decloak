package judge

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Panel strategies decide how member verdicts combine.
const (
	// StrategyAny flags a file when any member flags it. It maximizes recall.
	StrategyAny = "any"
	// StrategyMajority flags a file when at least half the members flag it,
	// trading some recall for fewer single-model false positives. A tie flags
	// the file, since this is a security check.
	StrategyMajority = "majority"
)

// Vote is one panel member's verdict on a file.
type Vote struct {
	Model      string  `json:"model"`
	Verdict    string  `json:"verdict"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
}

// Panel asks several judges about the same file and combines their verdicts.
type Panel struct {
	members  []*Client
	strategy string
}

// NewPanel returns a panel over members. It needs at least two members.
func NewPanel(members []*Client, strategy string) (*Panel, error) {
	if len(members) < 2 {
		return nil, fmt.Errorf("a judge panel needs at least two models, got %d", len(members))
	}
	switch strategy {
	case "":
		strategy = StrategyAny
	case StrategyAny, StrategyMajority:
	default:
		return nil, fmt.Errorf("unknown panel strategy %q: expected %s or %s", strategy, StrategyAny, StrategyMajority)
	}
	return &Panel{members: members, strategy: strategy}, nil
}

// Model names the panel, for reports.
func (p *Panel) Model() string { return strings.Join(p.memberNames(), "+") }

// Endpoint lists member endpoints, for diagnostics.
func (p *Panel) Endpoint() string {
	eps := make([]string, len(p.members))
	for i, m := range p.members {
		eps[i] = m.Endpoint()
	}
	return strings.Join(eps, ", ")
}

// Analyze asks every member concurrently. Any member error fails the file:
// a silent member could have been the one that flagged it, so the panel never
// guesses around a missing vote.
func (p *Panel) Analyze(ctx context.Context, file File) (Verdict, Usage, error) {
	verdicts := make([]Verdict, len(p.members))
	usages := make([]Usage, len(p.members))
	errs := make([]error, len(p.members))
	var wg sync.WaitGroup
	for i, m := range p.members {
		wg.Add(1)
		go func(i int, m *Client) {
			defer wg.Done()
			verdicts[i], usages[i], errs[i] = m.Analyze(ctx, file)
		}(i, m)
	}
	wg.Wait()

	total := Usage{Cached: true}
	for i, u := range usages {
		total.PromptTokens += u.PromptTokens
		total.CompletionTokens += u.CompletionTokens
		total.TotalTokens += u.TotalTokens
		total.Cached = total.Cached && u.Cached && errs[i] == nil
	}
	for i, err := range errs {
		if err != nil {
			return Verdict{}, total, fmt.Errorf("judge %s: %w", p.members[i].Model(), err)
		}
	}
	return combine(verdicts, p.memberNames(), p.strategy), total, nil
}

func (p *Panel) memberNames() []string {
	names := make([]string, len(p.members))
	for i, m := range p.members {
		names[i] = m.Model()
	}
	return names
}

// combine merges member verdicts under strategy and records every vote.
func combine(verdicts []Verdict, names []string, strategy string) Verdict {
	votes := make([]Vote, len(verdicts))
	var flagged, cleared []Verdict
	truncated := false
	chunks := 0
	for i, v := range verdicts {
		votes[i] = Vote{Model: names[i], Verdict: v.Verdict, Severity: v.Severity, Confidence: v.Confidence}
		if v.IsBenign() {
			cleared = append(cleared, v)
		} else {
			flagged = append(flagged, v)
		}
		truncated = truncated || v.Truncated
		if v.Chunks > chunks {
			chunks = v.Chunks
		}
	}

	var out Verdict
	switch {
	case len(flagged) == 0:
		out = mostSevere(cleared)
	case strategy == StrategyMajority && len(flagged)*2 < len(verdicts):
		out = mostSevere(cleared)
		out.Reason = fmt.Sprintf("%d of %d judges flagged this file; majority cleared it. %s",
			len(flagged), len(verdicts), out.Reason)
	default:
		out = mostSevere(flagged)
		if len(flagged) < len(verdicts) {
			out.Reason = fmt.Sprintf("%d of %d judges flagged this file. %s", len(flagged), len(verdicts), out.Reason)
		}
	}
	out.Votes = votes
	out.Truncated = truncated
	out.Chunks = chunks
	return out
}
