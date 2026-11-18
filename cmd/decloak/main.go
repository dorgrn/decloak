package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/dorgrn/decloak/internal/lock"
	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/output"
	"github.com/dorgrn/decloak/internal/rules"
	"github.com/dorgrn/decloak/internal/traversal"
	"github.com/dorgrn/decloak/internal/version"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	Format        string
	FailOn        string
	MaxBlankLines int
	MaxFileSizeMB int64
	Workers       int
	ResolveMCP    bool
	Verbose       bool
	StdinPaths    bool
	Policy        bool
}

const exitFindings = 1

func main() {
	opts := &ScanOptions{}

	rootCmd := &cobra.Command{
		Use:   "decloak",
		Short: "See what's hiding in your AI agent's skills, rules, and MCP servers, without running them",
		Long: `decloak is a 100% offline static scanner for AI agent instructions (AGENTS.md,
SKILL.md, CLAUDE.md, rules files) and local MCP servers. It parses Markdown,
Python, JavaScript, TypeScript, TSX/JSX, shell, and PowerShell to find hidden
prompt injections, invisible Unicode, encoded payloads, download-and-exec
chains, image-carried instructions, and credential exfiltration directives.

decloak never executes scanned code and contains no network client.`,
		SilenceUsage: true,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Scan files or directories (default: current directory)",
		Example: `  decloak scan .
  decloak scan ~/.claude/skills --format sarif
  git diff --name-only origin/main... | decloak scan --stdin-paths`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if opts.StdinPaths {
				var err error
				if paths, err = readPaths(os.Stdin); err != nil {
					return err
				}
				if len(paths) == 0 {
					return report(opts, nil)
				}
			} else if len(paths) == 0 {
				paths = []string{"."}
			}
			findings, err := scanPaths(opts, paths)
			if err != nil {
				return err
			}
			return report(opts, findings)
		},
	}
	addScanFlags(scanCmd, opts)
	scanCmd.Flags().BoolVar(&opts.StdinPaths, "stdin-paths", false, "Read newline-separated paths to scan from stdin (for changed-files / PR mode)")

	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Find and scan every agent skill, rules file, and MCP config installed for this user",
		Long: `audit discovers instruction files, skills, and MCP configurations for Claude
Code, Claude Desktop, Cursor, Windsurf, VS Code, GitHub Copilot, Codex, Gemini
CLI, OpenCode, Continue, Kiro, Amp, Roo Code, Cline, and Zed in your home
directory, then scans them. Everything stays on this machine.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			locs := traversal.AgentLocations(home)
			if len(locs) == 0 {
				fmt.Fprintln(os.Stderr, "No agent configuration found in", home)
				return report(opts, nil)
			}
			paths := make([]string, 0, len(locs))
			fmt.Fprintf(os.Stderr, "Scanning %d agent locations:\n", len(locs))
			for _, loc := range locs {
				fmt.Fprintf(os.Stderr, "  %-15s %s\n", loc.Agent, output.DisplayPath(loc.Path))
				paths = append(paths, loc.Path)
			}
			fmt.Fprintln(os.Stderr)
			findings, err := scanPaths(opts, paths)
			if err != nil {
				return err
			}
			return report(opts, findings)
		},
	}
	addScanFlags(auditCmd, opts)

	var lockFile string
	lockCmd := &cobra.Command{
		Use:   "lock [path...]",
		Short: "Record SHA-256 hashes of agent files so later changes (rug pulls) are detected",
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := discover(opts, defaultPaths(args))
			if err != nil {
				return err
			}
			lf := lock.Build(targets)
			if err := lf.Write(lockFile); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Locked %d files to %s\n", len(lf.Files), lockFile)
			return nil
		},
	}
	verifyCmd := &cobra.Command{
		Use:   "verify [path...]",
		Short: "Fail if any agent file changed, appeared, or disappeared since `decloak lock`",
		RunE: func(cmd *cobra.Command, args []string) error {
			want, err := lock.Read(lockFile)
			if err != nil {
				return err
			}
			targets, err := discover(opts, defaultPaths(args))
			if err != nil {
				return err
			}
			drift := want.Diff(lock.Build(targets))
			if len(drift) == 0 {
				fmt.Fprintf(os.Stderr, "OK: %d files match %s\n", len(want.Files), lockFile)
				return nil
			}
			for _, d := range drift {
				fmt.Printf("%-8s %s\n", d.Kind, d.Path)
			}
			fmt.Fprintf(os.Stderr, "\n%d files drifted from %s. Review the changes, then run `decloak lock` to accept them.\n", len(drift), lockFile)
			os.Exit(exitFindings)
			return nil
		},
	}
	for _, c := range []*cobra.Command{lockCmd, verifyCmd} {
		c.Flags().StringVar(&lockFile, "lock-file", "decloak.lock", "Path to the lock file")
		c.Flags().BoolVar(&opts.ResolveMCP, "resolve-mcp", true, "Include local MCP server scripts referenced by MCP configs")
		c.Flags().Int64Var(&opts.MaxFileSizeMB, "max-file-size-mb", 10, "Maximum file size in MB")
	}

	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "List all detection rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := rules.NewDefaultRegistry()
			if err != nil {
				return err
			}
			for _, r := range reg.Rules() {
				suffix := ""
				if strings.HasPrefix(r.ID, "POL-") {
					suffix = " [opt-in: --policy]"
				}
				fmt.Printf("%-14s [%-8s] (%s) %s%s\n", r.ID, r.Severity, r.Language, r.Description, suffix)
			}
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the decloak version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.String())
		},
	}

	rootCmd.AddCommand(scanCmd, auditCmd, lockCmd, verifyCmd, rulesCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func addScanFlags(cmd *cobra.Command, opts *ScanOptions) {
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "Output format: table, json, or sarif")
	cmd.Flags().StringVar(&opts.FailOn, "fail-on", "high", "Exit with code 1 if any finding >= severity (critical, high, medium, low)")
	cmd.Flags().IntVar(&opts.MaxBlankLines, "max-blank-lines", 50, "Consecutive blank-line threshold for Markdown padding concealment")
	cmd.Flags().Int64Var(&opts.MaxFileSizeMB, "max-file-size-mb", 10, "Maximum file size in MB to parse")
	cmd.Flags().IntVarP(&opts.Workers, "workers", "w", runtime.NumCPU(), "Number of concurrent worker goroutines")
	cmd.Flags().BoolVar(&opts.ResolveMCP, "resolve-mcp", true, "Scan local server scripts referenced by MCP configs")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Verbose diagnostics on stderr")
	cmd.Flags().BoolVar(&opts.Policy, "policy", false, "Enable the capability/policy layer (POL-* rules): visible dangerous behavior, not just concealed content")
}

func defaultPaths(args []string) []string {
	if len(args) == 0 {
		return []string{"."}
	}
	return args
}

// readPaths reads newline-separated paths, skipping blanks and files that no
// longer exist (deleted in the diff).
func readPaths(r io.Reader) ([]string, error) {
	var paths []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		p := sc.Text()
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		paths = append(paths, p)
	}
	return paths, sc.Err()
}

func discover(opts *ScanOptions, paths []string) ([]model.TargetFile, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	walker := traversal.NewWalker(traversal.WalkerConfig{
		MaxFileSizeBytes: opts.MaxFileSizeMB * 1024 * 1024,
		ResolveMCP:       opts.ResolveMCP,
		Verbose:          opts.Verbose,
	})
	targets, err := walker.DiscoverAll(ctx, paths)
	if err != nil {
		return nil, fmt.Errorf("target discovery failed: %w", err)
	}
	return targets, nil
}

func scanPaths(opts *ScanOptions, paths []string) ([]model.Finding, error) {
	if _, err := model.ParseSeverity(opts.FailOn); err != nil {
		return nil, err
	}
	reg, err := rules.NewDefaultRegistry()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule registry: %w", err)
	}
	targets, err := discover(opts, paths)
	if err != nil {
		return nil, err
	}
	engine := rules.NewEngine(reg, rules.EngineConfig{
		Workers:       opts.Workers,
		MaxBlankLines: opts.MaxBlankLines,
		Verbose:       opts.Verbose,
		Policy:        opts.Policy,
	})
	findings, err := engine.Run(context.Background(), targets)
	if err != nil {
		return nil, fmt.Errorf("scan execution failed: %w", err)
	}
	return findings, nil
}

func report(opts *ScanOptions, findings []model.Finding) error {
	threshold, err := model.ParseSeverity(opts.FailOn)
	if err != nil {
		return err
	}
	reporter, err := output.NewReporter(opts.Format, os.Stdout)
	if err != nil {
		return err
	}
	if err := reporter.Write(findings); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	if model.ShouldFail(findings, threshold) {
		os.Exit(exitFindings)
	}
	return nil
}
