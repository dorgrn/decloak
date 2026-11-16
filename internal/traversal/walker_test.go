package traversal

import (
	"testing"

	"github.com/dorgrn/decloak/internal/model"
)

func TestClassifyFile(t *testing.T) {
	tests := []struct {
		path string
		want model.Language
		ok   bool
	}{
		{path: "AGENTS.md", want: model.LangMarkdown, ok: true},
		{path: "SKILL.md", want: model.LangMarkdown, ok: true},
		{path: "tool.py", want: model.LangPython, ok: true},
		{path: "server.js", want: model.LangJavaScript, ok: true},
		{path: "server.mjs", want: model.LangJavaScript, ok: true},
		{path: "server.ts", want: model.LangTypeScript, ok: true},
		{path: "server.mts", want: model.LangTypeScript, ok: true},
		{path: "server.cts", want: model.LangTypeScript, ok: true},
		{path: "view.tsx", want: model.LangTSX, ok: true},
		{path: "view.jsx", want: model.LangTSX, ok: true},
		{path: "install.sh", want: model.LangShell, ok: true},
		{path: "install.bash", want: model.LangShell, ok: true},
		{path: ".zshrc", want: model.LangShell, ok: true},
		{path: "profile.ps1", want: model.LangPowerShell, ok: true},
		{path: "module.psm1", want: model.LangPowerShell, ok: true},
		{path: "GEMINI.md", want: model.LangMarkdown, ok: true},
		{path: ".clinerules", want: model.LangMarkdown, ok: true},
		{path: ".cursor/rules/style.mdc", want: model.LangMarkdown, ok: true},
		{path: "README.rst", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := ClassifyFile(tt.path)
			if ok != tt.ok {
				t.Fatalf("ClassifyFile(%q) ok = %v, want %v", tt.path, ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("ClassifyFile(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
