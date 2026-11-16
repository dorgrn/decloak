package traversal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dorgrn/decloak/internal/model"
)

func TestResolveMCPServerScripts(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"server.py", "server.js", "server.ts", "server.tsx", "setup.sh", "server.ps1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	config := `{
  "mcpServers": {
    "python-server": {"command": "python", "args": ["server.py"]},
    "javascript-server": {"command": "node", "args": ["server.js"]},
    "typescript-server": {"command": "node", "args": ["server.ts"]},
    "tsx-server": {"command": "node", "args": ["server.tsx"]},
    "shell-server": {"command": "bash", "args": ["setup.sh"]},
    "powershell-server": {"command": "pwsh", "args": ["server.ps1"]},
    "remote-package": {"command": "npx", "args": ["-y", "some-mcp-package"]}
  }
}`
	configPath := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	targets, err := ResolveMCPServerScripts(configPath)
	if err != nil {
		t.Fatalf("ResolveMCPServerScripts: %v", err)
	}

	got := make(map[model.Language]string)
	for _, target := range targets {
		got[target.Language] = filepath.Base(target.Path)
	}

	want := map[model.Language]string{
		model.LangPython:     "server.py",
		model.LangJavaScript: "server.js",
		model.LangTypeScript: "server.ts",
		model.LangTSX:        "server.tsx",
		model.LangShell:      "setup.sh",
		model.LangPowerShell: "server.ps1",
	}
	for lang, wantFile := range want {
		if got[lang] != wantFile {
			t.Errorf("language %s resolved to %q, want %q", lang, got[lang], wantFile)
		}
	}
	if len(targets) != len(want) {
		t.Errorf("resolved %d scripts, want %d", len(targets), len(want))
	}
}

func TestResolveMCPServerScriptsMalformed(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), ".mcp.json")
	if err := os.WriteFile(configPath, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := ResolveMCPServerScripts(configPath); err == nil {
		t.Fatal("expected malformed MCP config to return an error")
	}
}
