package traversal

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

type WalkerConfig struct {
	MaxFileSizeBytes int64
	ResolveMCP       bool
	Verbose          bool
}

type Walker struct {
	cfg        WalkerConfig
	ignoreDirs map[string]struct{}
}

func NewWalker(cfg WalkerConfig) *Walker {
	if cfg.MaxFileSizeBytes <= 0 {
		cfg.MaxFileSizeBytes = 10 * 1024 * 1024
	}
	return &Walker{
		cfg: cfg,
		ignoreDirs: map[string]struct{}{
			".git":          {},
			"node_modules":  {},
			".venv":         {},
			"venv":          {},
			"vendor":        {},
			"dist":          {},
			"build":         {},
			"__pycache__":   {},
			"site-packages": {},
			".tox":          {},
			".mypy_cache":   {},
		},
	}
}

// Discover walks rootPath, classifies agent Markdown and code files, and optionally
// parses MCP configuration files to include external/local server entrypoint scripts.
func (w *Walker) Discover(ctx context.Context, rootPath string) ([]model.TargetFile, error) {
	return w.DiscoverAll(ctx, []string{rootPath})
}

// DiscoverAll runs Discover over several roots and returns each file once.
func (w *Walker) DiscoverAll(ctx context.Context, roots []string) ([]model.TargetFile, error) {
	seen := make(map[string]struct{})
	var targets []model.TargetFile
	for _, root := range roots {
		if err := w.discoverInto(ctx, root, seen, &targets); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func (w *Walker) discoverInto(ctx context.Context, rootPath string, seen map[string]struct{}, out *[]model.TargetFile) error {
	targets := *out
	defer func() { *out = targets }()

	addTarget := func(path string, lang model.Language, origin string) {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = filepath.Clean(path)
		}
		if _, exists := seen[abs]; exists {
			return
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() || info.Size() > w.cfg.MaxFileSizeBytes {
			return
		}
		seen[abs] = struct{}{}
		targets = append(targets, model.TargetFile{
			Path:         path,
			Language:     lang,
			SourceOrigin: origin,
		})
	}

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// An unreadable entry below the root should not abort the whole scan.
			if path != rootPath {
				if w.cfg.Verbose {
					fmt.Fprintf(os.Stderr, "[decloak] warning: skipping %s: %v\n", path, walkErr)
				}
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		name := d.Name()
		if d.IsDir() {
			if _, skip := w.ignoreDirs[name]; skip && path != rootPath {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file is an MCP configuration manifest
		if w.cfg.ResolveMCP && IsMCPConfigFile(path) {
			mcpTargets, err := ResolveMCPServerScripts(path)
			if err != nil && w.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "[decloak] warning: failed to parse MCP config %s: %v\n", path, err)
			}
			for _, mt := range mcpTargets {
				addTarget(mt.Path, mt.Language, mt.SourceOrigin)
			}
		}

		if lang, ok := ClassifyFile(path); ok {
			addTarget(path, lang, "walk")
		}
		return nil
	})

	return err
}

// ClassifyFile maps agent instruction files and MCP server scripts to a Tree-sitter grammar.
func ClassifyFile(path string) (model.Language, bool) {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	switch base {
	case "agents.md", "skill.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules":
		return model.LangMarkdown, true
	case ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile":
		return model.LangShell, true
	}

	switch ext {
	case ".md", ".markdown", ".mdc":
		return model.LangMarkdown, true
	case ".py", ".pyw":
		return model.LangPython, true
	case ".js", ".mjs", ".cjs":
		return model.LangJavaScript, true
	case ".ts", ".mts", ".cts":
		return model.LangTypeScript, true
	case ".tsx", ".jsx":
		return model.LangTSX, true
	case ".sh", ".bash", ".zsh", ".ksh", ".dash":
		return model.LangShell, true
	case ".ps1", ".psm1":
		return model.LangPowerShell, true
	default:
		return "", false
	}
}
