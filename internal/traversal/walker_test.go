package traversal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
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

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		mustWrite(t, filepath.Join(root, rel), content)
	}
}

func relPaths(t *testing.T, root string, targets []model.TargetFile) []string {
	t.Helper()
	var got []string
	for _, tf := range targets {
		rel, err := filepath.Rel(root, tf.Path)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, filepath.ToSlash(rel))
	}
	sort.Strings(got)
	return got
}

func TestWalkerDiscoverMatchesAgentFilenames(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"SKILL.md":                  "# skill",
		"AGENTS.md":                 "# agents",
		".cursorrules":              "rules",
		".cursor/rules/style.mdc":   "style",
		"scripts/run.sh":            "echo hi",
		"README.rst":                "ignored",
		"data.json":                 "{}",
		"nested/deep/helper.py":     "print(1)",
		"nested/deep/notes.txt":     "ignored",
		"nested/CLAUDE.md":          "# claude",
		"nested/deep/component.tsx": "export {}",
	})

	targets, err := NewWalker(WalkerConfig{}).Discover(context.Background(), root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	want := []string{
		".cursor/rules/style.mdc",
		".cursorrules",
		"AGENTS.md",
		"SKILL.md",
		"nested/CLAUDE.md",
		"nested/deep/component.tsx",
		"nested/deep/helper.py",
		"scripts/run.sh",
	}
	if got := relPaths(t, root, targets); !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
	for _, tf := range targets {
		if tf.SourceOrigin != "walk" {
			t.Errorf("%s origin = %q, want walk", tf.Path, tf.SourceOrigin)
		}
	}
}

func TestWalkerDiscoverAssignsLanguages(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"SKILL.md": "#", "a.py": "x=1", "b.ps1": "1"})

	targets, err := NewWalker(WalkerConfig{}).Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Language{}
	for _, tf := range targets {
		got[filepath.Base(tf.Path)] = tf.Language
	}
	want := map[string]model.Language{"SKILL.md": model.LangMarkdown, "a.py": model.LangPython, "b.ps1": model.LangPowerShell}
	for name, lang := range want {
		if got[name] != lang {
			t.Errorf("%s language = %q, want %q", name, got[name], lang)
		}
	}
}

func TestWalkerDiscoverSkipsIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"SKILL.md":                      "# keep",
		"node_modules/pkg/AGENTS.md":    "skip",
		".git/hooks/pre-commit.sh":      "skip",
		"venv/lib/tool.py":              "skip",
		"vendor/x/CLAUDE.md":            "skip",
		"src/build/output.md":           "skip",
		"src/site-packages/mod.py":      "skip",
		"docs/__pycache__/cache.py":     "skip",
		"src/keep/AGENTS.md":            "keep",
		"dist/bundle.js":                "skip",
		"deep/.tox/env/tool.py":         "skip",
		"deep/.mypy_cache/meta/tool.py": "skip",
	})

	targets, err := NewWalker(WalkerConfig{}).Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SKILL.md", "src/keep/AGENTS.md"}
	if got := relPaths(t, root, targets); !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
}

func TestWalkerDiscoverScansIgnoredDirNamedAsRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "node_modules")
	writeTree(t, root, map[string]string{"AGENTS.md": "# explicit root"})

	targets, err := NewWalker(WalkerConfig{}).Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %+v, want the explicit root's AGENTS.md", targets)
	}
}

func TestWalkerDiscoverAcceptsFileRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "SKILL.md")
	mustWrite(t, file, "# skill")

	targets, err := NewWalker(WalkerConfig{}).Discover(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Path != file {
		t.Fatalf("targets = %+v, want only %s", targets, file)
	}
}

func TestWalkerDiscoverSkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"small.md": strings.Repeat("a", 100),
		"exact.md": strings.Repeat("a", 200),
		"big.md":   strings.Repeat("a", 201),
	})

	targets, err := NewWalker(WalkerConfig{MaxFileSizeBytes: 200}).Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"exact.md", "small.md"}
	if got := relPaths(t, root, targets); !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
}

func TestNewWalkerDefaultsMaxFileSizeToTenMB(t *testing.T) {
	for _, size := range []int64{0, -5} {
		w := NewWalker(WalkerConfig{MaxFileSizeBytes: size})
		if w.cfg.MaxFileSizeBytes != 10*1024*1024 {
			t.Errorf("MaxFileSizeBytes(%d) -> %d, want 10 MiB", size, w.cfg.MaxFileSizeBytes)
		}
	}
	if w := NewWalker(WalkerConfig{MaxFileSizeBytes: 42}); w.cfg.MaxFileSizeBytes != 42 {
		t.Errorf("explicit MaxFileSizeBytes overridden: %d", w.cfg.MaxFileSizeBytes)
	}
}

func TestWalkerDiscoverResolvesMCPServerScripts(t *testing.T) {
	root := t.TempDir()
	// The server script lives in a dir the walk would not classify on its own
	// (ignored "vendor"), so it is only found through the MCP config.
	writeTree(t, root, map[string]string{
		".mcp.json":        `{"mcpServers":{"demo":{"command":"python","args":["vendor/server.py"]}}}`,
		"vendor/server.py": "print('server')",
	})

	t.Run("enabled", func(t *testing.T) {
		targets, err := NewWalker(WalkerConfig{ResolveMCP: true}).Discover(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := relPaths(t, root, targets), []string{"vendor/server.py"}; !slices.Equal(got, want) {
			t.Fatalf("discovered = %v, want %v", got, want)
		}
		if origin := targets[0].SourceOrigin; !strings.HasPrefix(origin, "mcp-config:") || !strings.HasSuffix(origin, "#demo") {
			t.Errorf("origin = %q, want mcp-config:<path>#demo", origin)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		targets, err := NewWalker(WalkerConfig{ResolveMCP: false}).Discover(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(targets) != 0 {
			t.Errorf("targets = %+v, want none when ResolveMCP is false", targets)
		}
	})
}

func TestWalkerDiscoverToleratesBrokenMCPConfig(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"mcp.json": "{not json",
		"SKILL.md": "# skill",
	})

	targets, err := NewWalker(WalkerConfig{ResolveMCP: true}).Discover(context.Background(), root)
	if err != nil {
		t.Fatalf("Discover must not fail on a malformed MCP config: %v", err)
	}
	if got, want := relPaths(t, root, targets), []string{"SKILL.md"}; !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
}

func TestWalkerDiscoverAllDeduplicatesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a/SKILL.md":  "# a",
		"b/AGENTS.md": "# b",
	})

	targets, err := NewWalker(WalkerConfig{}).DiscoverAll(context.Background(),
		[]string{root, filepath.Join(root, "a"), filepath.Join(root, "a", "SKILL.md")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/SKILL.md", "b/AGENTS.md"}
	if got := relPaths(t, root, targets); !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
}

func TestWalkerDiscoverAllWithNoRootsReturnsNothing(t *testing.T) {
	targets, err := NewWalker(WalkerConfig{}).DiscoverAll(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Errorf("targets = %+v, want none", targets)
	}
}

func TestWalkerDiscoverMissingRootReturnsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := NewWalker(WalkerConfig{}).Discover(context.Background(), missing); err == nil {
		t.Fatal("Discover on a missing root returned nil error")
	}
}

func TestWalkerDiscoverAllStopsOnFirstFailingRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "SKILL.md"), "# skill")
	missing := filepath.Join(root, "missing")

	targets, err := NewWalker(WalkerConfig{}).DiscoverAll(context.Background(), []string{root, missing})
	if err == nil {
		t.Fatal("expected an error for the missing root")
	}
	if targets != nil {
		t.Errorf("targets = %+v, want nil on error", targets)
	}
}

func TestWalkerDiscoverHonorsCancelledContext(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "SKILL.md"), "# skill")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewWalker(WalkerConfig{}).Discover(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestWalkerDiscoverSkipsUnreadableSubdirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced here")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"SKILL.md":         "# ok",
		"locked/AGENTS.md": "# hidden",
	})
	locked := filepath.Join(root, "locked")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec // G302: a directory must be traversable again so TempDir cleanup can remove it

	targets, err := NewWalker(WalkerConfig{Verbose: true}).Discover(context.Background(), root)
	if err != nil {
		t.Fatalf("an unreadable subdirectory must not abort the walk: %v", err)
	}
	if got, want := relPaths(t, root, targets), []string{"SKILL.md"}; !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v", got, want)
	}
}
