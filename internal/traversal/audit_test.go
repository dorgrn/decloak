package traversal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAgentLocationsFindsOnlyExisting(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".claude", "skills", "demo", "SKILL.md"), "# demo")
	mustWrite(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{}}`)
	mustWrite(t, filepath.Join(home, ".codex", "AGENTS.md"), "# rules")

	got := map[string]string{}
	for _, loc := range AgentLocations(home) {
		rel, _ := filepath.Rel(home, loc.Path)
		got[rel] = loc.Agent
	}

	want := map[string]string{
		filepath.Join(".claude", "skills"):   "Claude Code",
		filepath.Join(".cursor", "mcp.json"): "Cursor",
		filepath.Join(".codex", "AGENTS.md"): "Codex",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for path, agent := range want {
		if got[path] != agent {
			t.Errorf("%s: agent = %q, want %q", path, got[path], agent)
		}
	}
}

func TestResolveVSCodeServersKey(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "server.py"), "print('hi')")
	cfg := filepath.Join(dir, "mcp.json")
	mustWrite(t, cfg, `{"servers":{"demo":{"command":"python","args":["server.py"]}}}`)

	targets, err := ResolveMCPServerScripts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || filepath.Base(targets[0].Path) != "server.py" {
		t.Fatalf("targets = %+v, want server.py", targets)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
