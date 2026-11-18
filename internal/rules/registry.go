package rules

import (
	"embed"
	"fmt"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/parser"
	"github.com/odvcencio/gotreesitter"
)

//go:embed queries/*.scm
var embeddedQueries embed.FS

// CompiledRule holds metadata and the pre-compiled pure-Go gotreesitter Query.
type CompiledRule struct {
	ID          string
	Severity    model.Severity
	Language    model.Language
	Description string
	Remediation string
	QuerySource string
	Query       *gotreesitter.Query
}

// Registry stores all pre-compiled AST rules indexed by language.
type Registry struct {
	all    []CompiledRule
	byLang map[model.Language][]CompiledRule
}

type ruleSpec struct {
	id          string
	severity    model.Severity
	lang        model.Language
	file        string
	description string
	remediation string
}

var defaultRuleSpecs = []ruleSpec{
	{
		id:          "PY-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangPython,
		file:        "queries/py_sink_decode.scm",
		description: "Obfuscated decoding call (b64decode/fromhex/decompress) passed directly or through variable taint into a Python execution sink (eval/exec/os.system/subprocess)",
		remediation: "Remove dynamic execution of decoded payloads; inspect the decoded content and replace with static, auditable logic.",
	},
	{
		id:          "PY-OBF-002",
		severity:    model.SeverityHigh,
		lang:        model.LangPython,
		file:        "queries/py_chr_concat.scm",
		description: "Dynamic chr() character concatenation chain feeding into an execution sink or getattr/__import__",
		remediation: "Eliminate runtime chr() string construction inside execution or reflection calls.",
	},
	{
		id:          "JS-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangJavaScript,
		file:        "queries/js_sink_decode.scm",
		description: "Obfuscated decoding (atob/Buffer.from/fromCharCode) passed directly or through variable taint into a JavaScript execution sink (eval/Function/child_process)",
		remediation: "Remove eval/Function/child_process execution of base64 or character-code decoded strings.",
	},
	{
		id:          "TS-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangTypeScript,
		file:        "queries/js_sink_decode.scm",
		description: "Obfuscated decoding (atob/Buffer.from/fromCharCode) passed directly or through variable taint into a TypeScript execution sink (eval/Function/child_process)",
		remediation: "Remove eval/Function/child_process execution of base64 or character-code decoded strings.",
	},
	{
		id:          "TSX-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangTSX,
		file:        "queries/js_sink_decode.scm",
		description: "Obfuscated decoding (atob/Buffer.from/fromCharCode) passed directly or through variable taint into a TSX/JSX execution sink (eval/Function/child_process)",
		remediation: "Remove eval/Function/child_process execution of base64 or character-code decoded strings.",
	},
	{
		id:          "SH-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangShell,
		file:        "queries/sh_sink_decode.scm",
		description: "Base64/openssl/xxd decoding piped or substituted into a shell execution sink (eval/bash -c/sh -c)",
		remediation: "Remove dynamic execution of decoded shell payloads; replace with static, auditable commands.",
	},
	{
		id:          "SH-DL-001",
		severity:    model.SeverityCritical,
		lang:        model.LangShell,
		file:        "queries/sh_download_exec.scm",
		description: "Remote download (curl/wget/fetch) piped, piped through intermediate commands, or source-substituted into a shell execution sink",
		remediation: "Download to a file, verify integrity/signature, and review before executing.",
	},
	{
		id:          "PS-EXEC-001",
		severity:    model.SeverityCritical,
		lang:        model.LangPowerShell,
		file:        "queries/ps_sink_decode.scm",
		description: "PowerShell execution sink (iex/Invoke-Expression/powershell -EncodedCommand) receiving encoded, compressed, or downloaded payloads",
		remediation: "Remove dynamic execution of encoded or downloaded content; inspect the decoded payload and replace with auditable logic.",
	},
	{
		id:          "MD-INJ-001",
		severity:    model.SeverityHigh,
		lang:        model.LangMarkdown,
		file:        "queries/md_html_comment.scm",
		description: "Hidden AI prompt injection directive or shell command concealed inside a Markdown HTML comment (<!-- -->)",
		remediation: "Strip HTML comments containing agent instructions, tool overrides, or shell commands from AGENTS.md and SKILL.md.",
	},
}

// NewDefaultRegistry loads all embedded .scm files and compiles them against
// their respective pure-Go gotreesitter Language grammars.
func NewDefaultRegistry() (*Registry, error) {
	reg := &Registry{
		byLang: make(map[model.Language][]CompiledRule),
	}

	for _, spec := range defaultRuleSpecs {
		rawBytes, err := embeddedQueries.ReadFile(spec.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded query %s: %w", spec.file, err)
		}

		lang, err := parser.LanguageFor(spec.lang)
		if err != nil {
			return nil, err
		}

		q, err := gotreesitter.NewQuery(string(rawBytes), lang)
		if err != nil {
			return nil, fmt.Errorf("failed to compile query %s (%s): %w", spec.id, spec.file, err)
		}

		cr := CompiledRule{
			ID:          spec.id,
			Severity:    spec.severity,
			Language:    spec.lang,
			Description: spec.description,
			Remediation: spec.remediation,
			QuerySource: string(rawBytes),
			Query:       q,
		}
		reg.all = append(reg.all, cr)
		reg.byLang[spec.lang] = append(reg.byLang[spec.lang], cr)
	}

	return reg, nil
}

// Rules returns all compiled AST rules plus metadata for built-in lexical rules.
func (r *Registry) Rules() []CompiledRule {
	out := make([]CompiledRule, 0, len(r.all)+len(lexicalRules)+len(policyRules))
	out = append(out, r.all...)
	out = append(out, lexicalRules...)
	out = append(out, policyRules...)
	return out
}

// RulesForLanguage returns the pre-compiled Tree-sitter queries for a given grammar.
func (r *Registry) RulesForLanguage(lang model.Language) []CompiledRule {
	return r.byLang[lang]
}

// RuleByID returns the compiled rule with the given ID.
func (r *Registry) RuleByID(id string) (CompiledRule, bool) {
	for _, rule := range r.all {
		if rule.ID == id {
			return rule, true
		}
	}
	return CompiledRule{}, false
}
