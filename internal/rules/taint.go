package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/odvcencio/gotreesitter"
)

const maxTaintIterations = 32

var (
	// URL unquoting is ordinary input handling, not obfuscation.
	// Bare decompress() is ordinary streaming I/O; it only counts when it wraps
	// a text decoder (zlib.decompress(base64.b64decode(...))), which the
	// decoder alternatives already match.
	pythonDecodeCall = regexp.MustCompile(`(?i)\b(b64decode|urlsafe_b64decode|b32decode|b16decode|a85decode|b85decode|fromhex|a2b_base64|a2b_hex|decodebytes)\s*\(`)
	// Buffer.from only counts with a base64/hex encoding argument; a bare
	// `from(` matched Array.from and friends all over minified bundles.
	jsDecodeCall = regexp.MustCompile(`(\batob\s*\(|\bunescape\s*\(|\bfromCharCode\s*\(|\bfromBase64\s*\(|\bBuffer\.from\s*\([^)]*["'](base64|base64url|hex)["'])`)
)

type taintAssignment struct {
	variable string
	rhsText  string
}

type taintAnalyzer struct {
	lang        model.Language
	grammar     *gotreesitter.Language
	src         []byte
	assignments []taintAssignment
}

func newTaintAnalyzer(lang model.Language, grammar *gotreesitter.Language, src []byte) *taintAnalyzer {
	return &taintAnalyzer{lang: lang, grammar: grammar, src: src}
}

// supportsMultiHopTaint reports whether the language has a generic taint rule.
// Shell and PowerShell remain query-only.
func supportsMultiHopTaint(lang model.Language) bool {
	switch lang {
	case model.LangPython, model.LangJavaScript, model.LangTypeScript, model.LangTSX:
		return true
	default:
		return false
	}
}

func taintRuleID(lang model.Language) string {
	switch lang {
	case model.LangPython:
		return "PY-EXEC-001"
	case model.LangJavaScript:
		return "JS-EXEC-001"
	case model.LangTypeScript:
		return "TS-EXEC-001"
	case model.LangTSX:
		return "TSX-EXEC-001"
	default:
		return ""
	}
}

// evalMultiHopTaint computes the transitive closure of variable assignments
// whose right-hand side is a decoder call or another tainted variable, then
// flags execution sinks that consume a tainted variable.
//
// The Tree-sitter queries in queries/*.scm can only express fixed-hop taint
// (source assignment -> sink). This pass is flow-insensitive and scoped to a
// single file, which is sufficient to follow chains such as:
//
//	payload = b64decode(blob)
//	cmd = "sh -c " + payload
//	exec(cmd)
func (e *Engine) evalMultiHopTaint(
	root *gotreesitter.Node,
	grammar *gotreesitter.Language,
	src []byte,
	target model.TargetFile,
	ruleLang model.Language,
	baseLineOffset uint32,
) []model.Finding {
	if !supportsMultiHopTaint(ruleLang) {
		return nil
	}
	ruleID := taintRuleID(ruleLang)
	rule, ok := e.registry.RuleByID(ruleID)
	if !ok {
		return nil
	}

	a := newTaintAnalyzer(ruleLang, grammar, src)
	a.collectAssignments(root)
	tainted := a.taintedVariables()
	var findings []model.Finding
	a.walk(root, func(n *gotreesitter.Node) {
		fn := a.sinkFunction(n)
		if fn == "" || !isExecutionSink(ruleLang, fn) || a.isRegexOrForeignExec(n, fn) {
			return
		}
		args := n.ChildByFieldName("arguments", grammar)
		if args == nil || !containsTaintedIdentifier(args, src, tainted) {
			return
		}
		start := n.StartPoint()
		end := n.EndPoint()
		findings = append(findings, model.Finding{
			RuleID:       rule.ID,
			Severity:     rule.Severity,
			SeverityName: rule.Severity.String(),
			Language:     ruleLang,
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
	})

	return findings
}

func (a *taintAnalyzer) collectAssignments(root *gotreesitter.Node) {
	a.walk(root, func(n *gotreesitter.Node) {
		switch n.Type(a.grammar) {
		case "assignment":
			if a.lang != model.LangPython {
				return
			}
			a.recordAssignment(n, "left", "right")
		case "variable_declarator":
			if a.lang == model.LangPython {
				return
			}
			a.recordAssignment(n, "name", "value")
		case "assignment_expression":
			if a.lang == model.LangPython {
				return
			}
			a.recordAssignment(n, "left", "right")
		}
	})
}

func (a *taintAnalyzer) recordAssignment(n *gotreesitter.Node, lhsField, rhsField string) {
	left := n.ChildByFieldName(lhsField, a.grammar)
	right := n.ChildByFieldName(rhsField, a.grammar)
	if left == nil || right == nil || left.Type(a.grammar) != "identifier" {
		return
	}
	// A function value does not carry data: names inside its body are its own
	// locals, so `f = function(){ var str = ... }` must not inherit taint on `str`.
	switch right.Type(a.grammar) {
	case "function", "function_expression", "arrow_function", "generator_function", "class", "lambda":
		return
	}
	a.assignments = append(a.assignments, taintAssignment{
		variable: left.Text(a.src),
		rhsText:  right.Text(a.src),
	})
}

func (a *taintAnalyzer) taintedVariables() map[string]struct{} {
	tainted := make(map[string]struct{})
	var decode *regexp.Regexp
	if a.lang == model.LangPython {
		decode = pythonDecodeCall
	} else {
		decode = jsDecodeCall
	}

	for iteration := 0; iteration < maxTaintIterations; iteration++ {
		changed := false
		for _, assignment := range a.assignments {
			if _, already := tainted[assignment.variable]; already {
				continue
			}
			if decode.MatchString(assignment.rhsText) || containsTaintedIdentifierText(assignment.rhsText, tainted) {
				tainted[assignment.variable] = struct{}{}
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return tainted
}

func (a *taintAnalyzer) sinkFunction(n *gotreesitter.Node) string {
	switch n.Type(a.grammar) {
	case "call", "call_expression":
		fn := n.ChildByFieldName("function", a.grammar)
		if fn == nil {
			return ""
		}
		return lastIdentifier(fn.Text(a.src))
	case "new_expression":
		ctor := n.ChildByFieldName("constructor", a.grammar)
		if ctor == nil {
			return ""
		}
		return lastIdentifier(ctor.Text(a.src))
	default:
		return ""
	}
}

// isRegexOrForeignExec filters JavaScript `x.exec(...)` calls that are not
// child_process: RegExp.prototype.exec is by far the most common `.exec` in
// real (especially minified) code. A bare exec(...) or cp.exec / child_process.exec
// is still treated as a sink.
func (a *taintAnalyzer) isRegexOrForeignExec(n *gotreesitter.Node, fn string) bool {
	if a.lang == model.LangPython {
		return a.isForeignPythonCall(n, fn)
	}
	if fn != "exec" {
		return false
	}
	callee := n.ChildByFieldName("function", a.grammar)
	if callee == nil || callee.Type(a.grammar) != "member_expression" {
		return false
	}
	obj := callee.ChildByFieldName("object", a.grammar)
	if obj == nil {
		return false
	}
	switch obj.Type(a.grammar) {
	case "regex", "new_expression", "call_expression", "parenthesized_expression":
		return true
	}
	name := obj.Text(a.src)
	return !childProcessRe.MatchString(name)
}

// Generic method names are only execution sinks on the modules that define
// them: subprocess.run is a sink, client.call or self.run is not.
var pythonQualifiedSinks = map[string]*regexp.Regexp{
	"run":          regexp.MustCompile(`^(subprocess|sp|runpy)$`),
	"call":         regexp.MustCompile(`^(subprocess|sp)$`),
	"Popen":        regexp.MustCompile(`^(subprocess|sp)$`),
	"check_output": regexp.MustCompile(`^(subprocess|sp)$`),
	"system":       regexp.MustCompile(`^(os)$`),
	"popen":        regexp.MustCompile(`^(os)$`),
	// Bare eval/exec/compile are builtins; re.compile, pattern.exec, etc. are not.
	"eval":    regexp.MustCompile(`^(builtins)?$`),
	"exec":    regexp.MustCompile(`^(builtins)?$`),
	"compile": regexp.MustCompile(`^(builtins)?$`),
}

func (a *taintAnalyzer) isForeignPythonCall(n *gotreesitter.Node, fn string) bool {
	allowed, scoped := pythonQualifiedSinks[fn]
	if !scoped {
		return false
	}
	callee := n.ChildByFieldName("function", a.grammar)
	if callee == nil {
		return true
	}
	if callee.Type(a.grammar) != "attribute" {
		// Bare run()/call()/Popen() only count when imported from a sink module.
		return !allowed.MatchString("") && !a.importedFromSinkModule(fn)
	}
	obj := callee.ChildByFieldName("object", a.grammar)
	return obj == nil || !allowed.MatchString(obj.Text(a.src))
}

var fromSubprocessImportRe = regexp.MustCompile(`(?m)^\s*from\s+(subprocess|os|runpy)\s+import\s+([^\n]+)`)

func (a *taintAnalyzer) importedFromSinkModule(fn string) bool {
	for _, m := range fromSubprocessImportRe.FindAllSubmatch(a.src, -1) {
		for _, name := range strings.Split(string(m[2]), ",") {
			if strings.TrimSpace(strings.Fields(name + " ")[0]) == fn {
				return true
			}
		}
	}
	return false
}

var childProcessRe = regexp.MustCompile(`(?i)^(child_?process|cp|proc|childProcess|require\(["']child_process["']\))$`)

// isMinified reports bundled/minified sources: very long average line length.
func isMinified(src []byte) bool {
	if len(src) < 4096 {
		return false
	}
	lines := bytes.Count(src, []byte("\n")) + 1
	return len(src)/lines > 500
}

func (a *taintAnalyzer) walk(n *gotreesitter.Node, visit func(*gotreesitter.Node)) {
	if n == nil {
		return
	}
	visit(n)
	for i := 0; i < n.NamedChildCount(); i++ {
		a.walk(n.NamedChild(i), visit)
	}
}

func lastIdentifier(text string) string {
	text = strings.TrimSpace(text)
	if idx := strings.LastIndex(text, "."); idx >= 0 {
		text = text[idx+1:]
	}
	return strings.TrimSpace(text)
}

func isExecutionSink(lang model.Language, fn string) bool {
	switch lang {
	case model.LangPython:
		switch fn {
		case "eval", "exec", "compile", "__import__", "system", "popen", "run", "Popen", "call", "check_output",
			"execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
			"spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
			"run_module", "run_path":
			return true
		}
	case model.LangJavaScript, model.LangTypeScript, model.LangTSX:
		switch fn {
		case "eval", "Function", "exec", "execSync", "execFile", "execFileSync", "fork",
			"spawn", "spawnSync", "runInThisContext", "runInNewContext", "runInContext", "compileFunction":
			return true
		}
	}
	return false
}

func containsTaintedIdentifier(n *gotreesitter.Node, src []byte, tainted map[string]struct{}) bool {
	if n == nil || len(tainted) == 0 {
		return false
	}
	// Keyword argument names (subprocess.run(cmd, text=True)) are not values.
	return containsTaintedIdentifierText(keywordArgNameRe.ReplaceAllString(n.Text(src), "$1"), tainted)
}

var keywordArgNameRe = regexp.MustCompile(`\b[A-Za-z_]\w*\s*=([^=]|$)`)

func containsTaintedIdentifierText(text string, tainted map[string]struct{}) bool {
	if len(tainted) == 0 {
		return false
	}
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r != '_' && r != '$' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
	})
	for _, field := range fields {
		if _, ok := tainted[field]; ok {
			return true
		}
	}
	return false
}

func dedupeFindings(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%d\x00%d\x00%s",
			f.RuleID, f.FilePath, f.StartLine, f.EndLine, f.StartCol, f.EndCol, f.Snippet)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
