// Command decloak-judge is the optional semantic review companion to decloak.
// It is a separate binary so the main scanner stays offline by construction:
// only this binary talks to an LLM endpoint, and only when explicitly run.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/dorgrn/decloak/internal/judge"
	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/output"
	"github.com/dorgrn/decloak/internal/rules"
	"github.com/dorgrn/decloak/internal/traversal"
	"github.com/dorgrn/decloak/internal/version"
	"github.com/spf13/cobra"
)

const exitFindings = 1

type options struct {
	baseURL       string
	apiKey        string
	model         string
	format        string
	failOn        string
	workers       int
	timeout       time.Duration
	maxInputRunes int
	maxFileSizeMB int64
	policy        bool
	noStatic      bool
	verbose       bool
}

func main() {
	opts := &options{}
	rootCmd := &cobra.Command{
		Use:   "decloak-judge",
		Short: "Semantic LLM review for AI agent skills and rules (optional companion to decloak)",
		Long: `decloak-judge sends agent instruction files to an OpenAI-compatible chat
model and asks it to judge intent that static rules cannot see. It is a separate
binary so decloak itself stays completely offline.

The judge is advisory: it can be wrong, and it never replaces the deterministic
scan. File contents leave this machine and go to the configured endpoint.`,
		SilenceUsage: true,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Judge files or directories with an LLM (default: current directory)",
		Example: `  decloak-judge scan ~/.claude/skills --model gpt-5-mini
  decloak-judge scan . --base-url http://localhost:11434/v1 --model llama3.1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}
			return runScan(opts, paths)
		},
	}
	addJudgeFlags(scanCmd, opts)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the decloak-judge version",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println(version.String()) },
	}

	rootCmd.AddCommand(scanCmd, versionCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func addJudgeFlags(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.baseURL, "base-url", envOr("DECLOAK_JUDGE_BASE_URL", ""),
		"OpenAI-compatible API base URL (default https://api.openai.com/v1)")
	cmd.Flags().StringVar(&o.apiKey, "api-key", envOr("DECLOAK_JUDGE_API_KEY", os.Getenv("OPENAI_API_KEY")),
		"API key (or DECLOAK_JUDGE_API_KEY / OPENAI_API_KEY)")
	cmd.Flags().StringVar(&o.model, "model", envOr("DECLOAK_JUDGE_MODEL", ""),
		"Judge model name (or DECLOAK_JUDGE_MODEL)")
	cmd.Flags().StringVarP(&o.format, "format", "f", "table", "Output format: table, json, or sarif")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "high", "Exit with code 1 if any judge finding >= severity (critical, high, medium, low)")
	cmd.Flags().IntVarP(&o.workers, "workers", "w", 4, "Concurrent judge requests")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 90*time.Second, "Per-request timeout")
	cmd.Flags().IntVar(&o.maxInputRunes, "max-input-chars", 120000, "Maximum characters of file content sent to the judge")
	cmd.Flags().Int64Var(&o.maxFileSizeMB, "max-file-size-mb", 10, "Maximum file size in MB to scan")
	cmd.Flags().BoolVar(&o.policy, "policy", false, "Include policy-rule hints in the judge prompt")
	cmd.Flags().BoolVar(&o.noStatic, "no-static", false, "Do not include static findings as hints")
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "Print per-file verdicts and token usage to stderr")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func runScan(opts *options, paths []string) error {
	if _, err := model.ParseSeverity(opts.failOn); err != nil {
		return err
	}
	if opts.workers <= 0 {
		opts.workers = runtime.NumCPU()
	}
	client, err := judge.NewClient(judge.Config{
		BaseURL:       opts.baseURL,
		APIKey:        opts.apiKey,
		Model:         opts.model,
		Timeout:       opts.timeout,
		MaxInputRunes: opts.maxInputRunes,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Judge: %s at %s\n", client.Model(), client.Endpoint())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	walker := traversal.NewWalker(traversal.WalkerConfig{
		MaxFileSizeBytes: opts.maxFileSizeMB * 1024 * 1024,
		ResolveMCP:       true,
		Verbose:          opts.verbose,
	})
	targets, err := walker.DiscoverAll(ctx, paths)
	if err != nil {
		return fmt.Errorf("target discovery failed: %w", err)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "No agent files found.")
		return nil
	}

	static := map[string][]model.Finding{}
	if !opts.noStatic {
		reg, err := rules.NewDefaultRegistry()
		if err != nil {
			return fmt.Errorf("initialize rule registry: %w", err)
		}
		engine := rules.NewEngine(reg, rules.EngineConfig{
			Workers: opts.workers,
			Policy:  opts.policy,
			Verbose: opts.verbose,
		})
		found, err := engine.Run(ctx, targets)
		if err != nil {
			return fmt.Errorf("static scan failed: %w", err)
		}
		for _, f := range found {
			static[f.FilePath] = append(static[f.FilePath], f)
		}
	}

	findings, counts, errs := analyzeAll(ctx, client, targets, static, opts)
	sortFindings(findings)

	reporter, err := output.NewReporterAs("decloak-judge", opts.format, os.Stdout)
	if err != nil {
		return err
	}
	if err := reporter.Write(findings); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nJudged %d files: %d malicious, %d suspicious, %d benign, %d errors\n",
		len(targets), counts.malicious, counts.suspicious, counts.benign, len(errs))
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %v\n", e)
		}
		os.Exit(2)
	}

	threshold, _ := model.ParseSeverity(opts.failOn)
	if model.ShouldFail(findings, threshold) {
		os.Exit(exitFindings)
	}
	return nil
}

type counts struct {
	malicious  int
	suspicious int
	benign     int
}

type outcome struct {
	finding *model.Finding
	verdict string
	err     error
}

func analyzeAll(ctx context.Context, client *judge.Client, targets []model.TargetFile, static map[string][]model.Finding, opts *options) ([]model.Finding, counts, []error) {
	results := make([]outcome, len(targets))
	sem := make(chan struct{}, opts.workers)
	var wg sync.WaitGroup
	var stderrMu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		go func(i int, target model.TargetFile) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			src, err := os.ReadFile(target.Path)
			if err != nil {
				results[i].err = fmt.Errorf("%s: %w", target.Path, err)
				return
			}
			verdict, usage, err := client.Analyze(ctx, judge.File{
				Path:           target.Path,
				Language:       target.Language,
				Content:        string(src),
				StaticFindings: formatHints(static[target.Path]),
			})
			if err != nil {
				results[i].err = fmt.Errorf("%s: %w", target.Path, err)
				return
			}
			if opts.verbose {
				stderrMu.Lock()
				fmt.Fprintf(os.Stderr, "  %-12s %s (tokens %d)\n", verdict.Verdict, target.Path, usage.TotalTokens)
				stderrMu.Unlock()
			}
			results[i].verdict = verdict.Verdict
			if f, ok := judge.ToFinding(target, verdict, client.Model()); ok {
				results[i].finding = &f
			}
		}(i, target)
	}
	wg.Wait()

	var findings []model.Finding
	var errs []error
	var c counts
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		switch r.verdict {
		case "malicious":
			c.malicious++
		case "suspicious":
			c.suspicious++
		default:
			c.benign++
		}
		if r.finding != nil {
			findings = append(findings, *r.finding)
		}
	}
	return findings, c, errs
}

func formatHints(findings []model.Finding) []string {
	hints := make([]string, 0, len(findings))
	for _, f := range findings {
		hints = append(hints, fmt.Sprintf("%s (%s) line %d: %s", f.RuleID, f.SeverityName, f.StartLine, f.Message))
	}
	return hints
}

func sortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].StartLine < findings[j].StartLine
	})
}
