package traversal

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// AgentLocation is a well-known place where an AI agent keeps instructions,
// skills, or MCP server configuration in the user's home directory.
type AgentLocation struct {
	Agent string
	Path  string
}

// userAgentLocations lists per-user agent paths relative to the home directory.
// Directories are walked; files are scanned directly. Paths that do not exist
// are skipped, so listing an agent here costs nothing when it is not installed.
var userAgentLocations = []AgentLocation{
	{"Claude Code", ".claude/CLAUDE.md"},
	{"Claude Code", ".claude/skills"},
	{"Claude Code", ".claude/commands"},
	{"Claude Code", ".claude/agents"},
	{"Claude Code", ".claude/plugins"},
	{"Claude Code", ".claude.json"},
	{"Cursor", ".cursor/mcp.json"},
	{"Cursor", ".cursor/rules"},
	{"Cursor", ".cursor/skills"},
	{"Windsurf", ".codeium/windsurf/mcp_config.json"},
	{"Windsurf", ".codeium/windsurf/memories"},
	{"VS Code", ".vscode/mcp.json"},
	{"GitHub Copilot", ".copilot"},
	{"Codex", ".codex/AGENTS.md"},
	{"Codex", ".codex/config.toml"},
	{"Codex", ".codex/skills"},
	{"Codex", ".codex/prompts"},
	{"Gemini CLI", ".gemini/GEMINI.md"},
	{"Gemini CLI", ".gemini/settings.json"},
	{"Gemini CLI", ".gemini/extensions"},
	{"OpenCode", ".config/opencode"},
	{"Amp", ".config/agents/skills"},
	{"Amp", ".config/amp/settings.json"},
	{"Continue", ".continue"},
	{"Kiro", ".kiro"},
	{"OpenClaw", ".openclaw/workspace/skills"},
	{"Roo Code", ".roo"},
	{"Cline", "Documents/Cline/Rules"},
	{"Zed", ".config/zed/settings.json"},
	{"Generic", ".agents/skills"},
	{"Generic", ".config/.mcp"},
}

// AgentLocations returns the agent paths that exist under home, including
// OS-specific application-support locations (Claude Desktop, VS Code user MCP).
func AgentLocations(home string) []AgentLocation {
	candidates := make([]AgentLocation, 0, len(userAgentLocations)+4)
	for _, loc := range userAgentLocations {
		candidates = append(candidates, AgentLocation{loc.Agent, filepath.Join(home, loc.Path)})
	}
	candidates = append(candidates, appSupportLocations(home)...)

	var found []AgentLocation
	seen := make(map[string]struct{})
	for _, loc := range candidates {
		if _, err := os.Stat(loc.Path); err != nil {
			continue
		}
		if _, dup := seen[loc.Path]; dup {
			continue
		}
		seen[loc.Path] = struct{}{}
		found = append(found, loc)
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].Agent < found[j].Agent })
	return found
}

func appSupportLocations(home string) []AgentLocation {
	var base string
	switch runtime.GOOS {
	case "darwin":
		base = filepath.Join(home, "Library", "Application Support")
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			base = filepath.Join(home, "AppData", "Roaming")
		}
	default:
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(home, ".config")
		}
	}
	return []AgentLocation{
		{"Claude Desktop", filepath.Join(base, "Claude", "claude_desktop_config.json")},
		{"VS Code", filepath.Join(base, "Code", "User", "mcp.json")},
		{"Cursor", filepath.Join(base, "Cursor", "User", "mcp.json")},
	}
}
