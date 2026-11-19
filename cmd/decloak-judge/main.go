// Command decloak-judge is the optional semantic review companion to decloak.
// It is a separate binary so the main scanner stays offline by construction:
// only this binary talks to an LLM endpoint, and only when explicitly run.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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

const (
	exitClean    = 0
	exitFindings = 1
	exitError    = 2
)

type options struct {
	baseURL       string
	apiKey        string
	model         string
	models        []string
	strategy      string
	provider      string
	format        string
	failOn        string
	minConfidence float64
	workers       int
	timeout       time.Duration
	maxInputRunes int
	maxChunks     int
	maxOutput     int
	maxFileSizeMB int64
	cacheDir      string
	noCache       bool
	policy        bool
	noStatic      bool
	verbose       bool
}

// analyzer is the judge surface the scan needs; *judge.Client and
// *judge.Panel both satisfy it.
type analyzer interface {
	Analyze(ctx context.Context, file judge.File) (judge.Verdict, judge.Usage, error)
	Model() string
	Endpoint() string
}

// exitCodeError carries a process exit code out of a cobra command.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := newRootCmd(stdout, stderr)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	var ec exitCodeError
	switch {
	case errors.As(err, &ec):
		return ec.code
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	default:
		return exitClean
	}
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	opts := &options{}
	rootCmd := &cobra.Command{
		Use:   "decloak-judge",
		Short: "Semantic LLM review for AI agent skills and rules (optional companion to decloak)",
		Long: `decloak-judge sends agent instruction files to an OpenAI-compatible chat
model and asks it to judge intent that static rules cannot see. It is a separate
binary so decloak itself stays completely offline.

The judge is advisory: it can be wrong, and it never replaces the deterministic
scan. File contents leave this machine and go to the configured endpoint.

Use --provider opencode for OpenCode Zen (DeepSeek V4.1 Flash free by default),
or --base-url/--model for any other OpenAI-compatible endpoint. Pass --models
with two or more names to ask a panel of models on the same endpoint.`,
		SilenceUsage: true,
	}
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)

	scanCmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Judge files or directories with an LLM (default: current directory)",
		Example: `  decloak-judge scan ~/.claude/skills --provider opencode
  decloak-judge scan . --base-url http://localhost:11434/v1 --model llama3.1
  decloak-judge scan . --models llama3.1,qwen3 --strategy majority`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths := args
			if len(paths) == 0 {
				paths = []string{"."}
			}
			code, err := runScan(cmd.Context(), opts, paths, stdout, stderr)
			if err != nil {
				return err
			}
			if code != exitClean {
				return exitCodeError{code: code}
			}
			return nil
		},
	}
	addJudgeFlags(scanCmd, opts)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the decloak-judge version",
		Run:   func(cmd *cobra.Command, args []string) { _, _ = fmt.Fprintln(stdout, version.String()) },
	}

	rootCmd.AddCommand(scanCmd, versionCmd)
	// run prints errors itself so an exit-code carrier is never shown as one.
	rootCmd.SilenceErrors = true
	return rootCmd
}

func addJudgeFlags(cmd *cobra.Command, o *options) {
	cmd.Flags().StringVar(&o.provider, "provider", envOr("DECLOAK_JUDGE_PROVIDER", "openai"),
		"Provider preset: openai or opencode (opencode defaults to DeepSeek V4.1 Flash free)")
	cmd.Flags().StringVar(&o.baseURL, "base-url", envOr("DECLOAK_JUDGE_BASE_URL", ""),
		"OpenAI-compatible API base URL (default https://api.openai.com/v1)")
	cmd.Flags().StringVar(&o.apiKey, "api-key", envOr("DECLOAK_JUDGE_API_KEY", firstNonEmpty(os.Getenv("OPENCODE_API_KEY"), os.Getenv("OPENAI_API_KEY"))),
		"API key (or DECLOAK_JUDGE_API_KEY / OPENCODE_API_KEY / OPENAI_API_KEY)")
	cmd.Flags().StringVar(&o.model, "model", envOr("DECLOAK_JUDGE_MODEL", ""),
		"Judge model name (or DECLOAK_JUDGE_MODEL)")
	cmd.Flags().StringSliceVar(&o.models, "models", nil,
		"Comma-separated models on the same endpoint to judge as a panel (overrides --model)")
	cmd.Flags().StringVar(&o.strategy, "strategy", judge.StrategyAny,
		"Panel strategy: any (flag if any model flags) or majority (flag if at least half do)")
	cmd.Flags().StringVarP(&o.format, "format", "f", "table", "Output format: table, json, or sarif")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "high", "Exit with code 1 if any judge finding >= severity (critical, high, medium, low)")
	cmd.Flags().Float64Var(&o.minConfidence, "min-confidence", 0,
		"Drop judge findings below this confidence (0-1); dropped files still count in the summary")
	cmd.Flags().IntVarP(&o.workers, "workers", "w", 4, "Concurrent judge requests")
	cmd.Flags().DurationVar(&o.timeout, "timeout", 90*time.Second, "Per-request timeout")
	cmd.Flags().IntVar(&o.maxInputRunes, "max-input-chars", 120000, "Maximum characters of file content per judge request")
	cmd.Flags().IntVar(&o.maxChunks, "max-chunks", 8,
		"Maximum requests per file; larger files are split, and beyond this the middle is skipped")
	cmd.Flags().IntVar(&o.maxOutput, "max-output-tokens", 1024, "Maximum tokens in the judge's answer")
	cmd.Flags().Int64Var(&o.maxFileSizeMB, "max-file-size-mb", 10, "Maximum file size in MB to scan")
	cmd.Flags().StringVar(&o.cacheDir, "cache-dir", envOr("DECLOAK_JUDGE_CACHE_DIR", defaultCacheDir()),
		"Directory for cached verdicts (or DECLOAK_JUDGE_CACHE_DIR)")
	cmd.Flags().BoolVar(&o.noCache, "no-cache", false, "Disable the verdict cache")
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func defaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		return ""
	}
	return filepath.Join(dir, "decloak", "judge")
}

func applyProvider(opts *options) error {
	switch strings.ToLower(strings.TrimSpace(opts.provider)) {
	case "", "openai":
		return nil
	case "opencode":
		if opts.baseURL == "" {
			opts.baseURL = judge.OpenCodeBaseURL
		}
		if opts.model == "" && len(opts.models) == 0 {
			opts.model = judge.OpenCodeDefaultModel
		}
		if opts.apiKey == "" {
			opts.apiKey = os.Getenv("OPENCODE_API_KEY")
		}
		return nil
	default:
		return fmt.Errorf("unsupported provider %q: expected openai or opencode", opts.provider)
	}
}

// panelModels returns the cleaned, de-duplicated --models list.
func panelModels(raw []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range raw {
		m = strings.TrimSpace(m)
		if m != "" && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func newAnalyzer(opts *options, cacheDir string) (analyzer, error) {
	cfg := judge.Config{
		BaseURL:         opts.baseURL,
		APIKey:          opts.apiKey,
		Model:           opts.model,
		Timeout:         opts.timeout,
		MaxInputRunes:   opts.maxInputRunes,
		MaxChunks:       opts.maxChunks,
		MaxOutputTokens: opts.maxOutput,
		CacheDir:        cacheDir,
	}
	models := panelModels(opts.models)
	switch len(models) {
	case 0:
		return judge.NewClient(cfg)
	case 1:
		cfg.Model = models[0]
		return judge.NewClient(cfg)
	}
	members := make([]*judge.Client, 0, len(models))
	for _, m := range models {
		cfg.Model = m
		c, err := judge.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		members = append(members, c)
	}
	return judge.NewPanel(members, opts.strategy)
}

func runScan(ctx context.Context, opts *options, paths []string, stdout, stderr io.Writer) (int, error) {
	threshold, err := model.ParseSeverity(opts.failOn)
	if err != nil {
		return exitError, err
	}
	if opts.minConfidence < 0 || opts.minConfidence > 1 {
		return exitError, fmt.Errorf("--min-confidence must be between 0 and 1, got %v", opts.minConfidence)
	}
	if err := applyProvider(opts); err != nil {
		return exitError, err
	}
	if opts.workers <= 0 {
		opts.workers = runtime.NumCPU()
	}
	cacheDir := opts.cacheDir
	if opts.noCache {
		cacheDir = ""
	}
	client, err := newAnalyzer(opts, cacheDir)
	if err != nil {
		return exitError, err
	}
	_, _ = fmt.Fprintf(stderr, "Judge: %s at %s\n", client.Model(), client.Endpoint())
	if cacheDir != "" {
		_, _ = fmt.Fprintf(stderr, "Cache: %s\n", cacheDir)
	} else {
		_, _ = fmt.Fprintln(stderr, "Cache: disabled")
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	walker := traversal.NewWalker(traversal.WalkerConfig{
		MaxFileSizeBytes: opts.maxFileSizeMB * 1024 * 1024,
		ResolveMCP:       true,
		Verbose:          opts.verbose,
	})
	targets, err := walker.DiscoverAll(ctx, paths)
	if err != nil {
		return exitError, fmt.Errorf("target discovery failed: %w", err)
	}
	if len(targets) == 0 {
		_, _ = fmt.Fprintln(stderr, "No agent files found.")
		return exitClean, nil
	}

	static := map[string][]model.Finding{}
	if !opts.noStatic {
		reg, err := rules.NewDefaultRegistry()
		if err != nil {
			return exitError, fmt.Errorf("initialize rule registry: %w", err)
		}
		engine := rules.NewEngine(reg, rules.EngineConfig{
			Workers: opts.workers,
			Policy:  opts.policy,
			Verbose: opts.verbose,
		})
		found, err := engine.Run(ctx, targets)
		if err != nil {
			return exitError, fmt.Errorf("static scan failed: %w", err)
		}
		for _, f := range found {
			static[f.FilePath] = append(static[f.FilePath], f)
		}
	}

	findings, c, errs := analyzeAll(ctx, client, targets, static, opts, stderr)
	sortFindings(findings)

	reporter, err := output.NewReporterAs("decloak-judge", opts.format, stdout)
	if err != nil {
		return exitError, err
	}
	if err := reporter.Write(findings); err != nil {
		return exitError, fmt.Errorf("write report: %w", err)
	}

	_, _ = fmt.Fprintf(stderr, "\nJudged %d files: %d malicious, %d suspicious, %d benign, %d cached, %d errors\n",
		len(targets), c.malicious, c.suspicious, c.benign, c.cached, len(errs))
	if c.lowConfidence > 0 {
		_, _ = fmt.Fprintf(stderr, "Dropped %d findings below --min-confidence %.2f\n", c.lowConfidence, opts.minConfidence)
	}
	if c.truncated > 0 {
		_, _ = fmt.Fprintf(stderr, "Warning: %d files were too large to judge in full; raise --max-chunks to cover them\n", c.truncated)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			_, _ = fmt.Fprintf(stderr, "  %v\n", e)
		}
		return exitError, nil
	}
	if model.ShouldFail(findings, threshold) {
		return exitFindings, nil
	}
	return exitClean, nil
}

type counts struct {
	malicious     int
	suspicious    int
	benign        int
	cached        int
	truncated     int
	lowConfidence int
}

type outcome struct {
	finding   *model.Finding
	verdict   string
	cached    bool
	truncated bool
	dropped   bool
	err       error
}

func analyzeAll(ctx context.Context, client analyzer, targets []model.TargetFile, static map[string][]model.Finding, opts *options, stderr io.Writer) ([]model.Finding, counts, []error) {
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
				if usage.Cached {
					_, _ = fmt.Fprintf(stderr, "  %-12s %s (cached)\n", verdict.Verdict, target.Path)
				} else {
					_, _ = fmt.Fprintf(stderr, "  %-12s %s (tokens %d)\n", verdict.Verdict, target.Path, usage.TotalTokens)
				}
				stderrMu.Unlock()
			}
			results[i].verdict = verdict.Verdict
			results[i].cached = usage.Cached
			results[i].truncated = verdict.Truncated
			f, ok := judge.ToFindingInContent(target, verdict, client.Model(), string(src))
			if !ok {
				return
			}
			if verdict.Confidence < opts.minConfidence {
				results[i].dropped = true
				return
			}
			results[i].finding = &f
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
		if r.cached {
			c.cached++
		}
		if r.truncated {
			c.truncated++
		}
		if r.dropped {
			c.lowConfidence++
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
