package rules

import (
	"regexp"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/odvcencio/gotreesitter"
)

var (
	shellDecoderRe = regexp.MustCompile(`(?i)(base64[[:space:]]+(-d|--decode)|openssl[[:space:]]+enc[[:space:]]+-d|xxd[[:space:]]+-r|uudecode)`)
	shellSinkRe    = regexp.MustCompile(`^(eval|bash|sh|zsh|dash|ksh)$`)
)

// shellTaint flags eval/bash -c style commands that expand a variable holding
// decoded content, following chains such as:
//
//	p=$(echo ... | base64 -d)
//	q="$p"
//	eval "$q"
//
// It runs in a single tree walk plus a fixed-point pass over assignments, so
// cost is linear in file size.
func (e *Engine) shellTaint(root *gotreesitter.Node, lang *gotreesitter.Language, src []byte, target model.TargetFile, baseLineOffset uint32) []model.Finding {
	rule, ok := e.registry.RuleByID("SH-EXEC-001")
	if !ok {
		return nil
	}

	type assignment struct {
		name string
		rhs  *gotreesitter.Node
	}
	var assigns []assignment
	var sinks []*gotreesitter.Node

	var walk func(n *gotreesitter.Node)
	walk = func(n *gotreesitter.Node) {
		switch n.Type(lang) {
		case "variable_assignment":
			name := n.ChildByFieldName("name", lang)
			value := n.ChildByFieldName("value", lang)
			if name != nil && value != nil {
				assigns = append(assigns, assignment{name.Text(src), value})
			}
		case "command":
			if cmd := n.ChildByFieldName("name", lang); cmd != nil && shellSinkRe.MatchString(cmd.Text(src)) {
				sinks = append(sinks, n)
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	if len(sinks) == 0 || len(assigns) == 0 {
		return nil
	}

	tainted := make(map[string]struct{})
	for changed := true; changed; {
		changed = false
		for _, a := range assigns {
			if _, done := tainted[a.name]; done {
				continue
			}
			if shellDecoderRe.MatchString(a.rhs.Text(src)) || expandsTainted(a.rhs, lang, src, tainted) {
				tainted[a.name] = struct{}{}
				changed = true
			}
		}
	}
	if len(tainted) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, n := range sinks {
		if !expandsTainted(n, lang, src, tainted) {
			continue
		}
		start, end := n.StartPoint(), n.EndPoint()
		findings = append(findings, model.Finding{
			RuleID:       rule.ID,
			Severity:     rule.Severity,
			SeverityName: rule.Severity.String(),
			Language:     model.LangShell,
			FilePath:     target.Path,
			SourceOrigin: target.SourceOrigin,
			StartLine:    baseLineOffset + start.Row + 1,
			EndLine:      baseLineOffset + end.Row + 1,
			StartCol:     start.Column + 1,
			EndCol:       end.Column + 1,
			Message:      rule.Description,
			Snippet:      oneLineSnippet(n.Text(src)),
			Remediation:  rule.Remediation,
		})
	}
	return findings
}

// expandsTainted reports whether n contains $var or ${var} for a tainted var.
func expandsTainted(n *gotreesitter.Node, lang *gotreesitter.Language, src []byte, tainted map[string]struct{}) bool {
	switch n.Type(lang) {
	case "simple_expansion", "expansion":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.Type(lang) == "variable_name" {
				if _, ok := tainted[c.Text(src)]; ok {
					return true
				}
			}
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if expandsTainted(n.NamedChild(i), lang, src, tainted) {
			return true
		}
	}
	return false
}
