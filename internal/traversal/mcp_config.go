package traversal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

// mcpConfigManifest models the standard MCP client configuration format used by
// Claude Desktop, Cursor (.cursor/mcp.json), and project-scoped .mcp.json files.
type mcpConfigManifest struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	// VS Code (.vscode/mcp.json) uses "servers".
	Servers map[string]mcpServerEntry `json:"servers"`
}

type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Cwd     string   `json:"cwd,omitempty"`
}

// IsMCPConfigFile returns true if the filename matches standard MCP configuration files.
func IsMCPConfigFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "managed-mcp.json", ".claude.json":
		return true
	default:
		return false
	}
}

// ResolveMCPServerScripts parses an MCP JSON configuration file and extracts any
// referenced local server scripts from `command` and `args`.
func ResolveMCPServerScripts(configPath string) ([]model.TargetFile, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var manifest mcpConfigManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}

	configDir := filepath.Dir(configPath)
	var discovered []model.TargetFile

	servers := manifest.MCPServers
	if len(servers) == 0 {
		servers = manifest.Servers
	}
	for serverName, entry := range servers {
		baseDir := configDir
		if entry.Cwd != "" {
			if filepath.IsAbs(entry.Cwd) {
				baseDir = entry.Cwd
			} else {
				baseDir = filepath.Join(configDir, entry.Cwd)
			}
		}

		candidates := append([]string{entry.Command}, entry.Args...)
		for _, tok := range candidates {
			tok = strings.TrimSpace(tok)
			if tok == "" || strings.HasPrefix(tok, "-") {
				continue
			}

			lang, ok := ClassifyFile(tok)
			if !ok || !isCodeLanguage(lang) {
				continue
			}

			resolvedPath := tok
			if !filepath.IsAbs(resolvedPath) {
				resolvedPath = filepath.Join(baseDir, resolvedPath)
			}

			if info, err := os.Stat(resolvedPath); err == nil && !info.IsDir() {
				discovered = append(discovered, model.TargetFile{
					Path:         resolvedPath,
					Language:     lang,
					SourceOrigin: fmt.Sprintf("mcp-config:%s#%s", configPath, serverName),
				})
			}
		}
	}

	return discovered, nil
}

func isCodeLanguage(lang model.Language) bool {
	switch lang {
	case model.LangPython, model.LangJavaScript, model.LangTypeScript, model.LangTSX, model.LangShell, model.LangPowerShell:
		return true
	default:
		return false
	}
}
