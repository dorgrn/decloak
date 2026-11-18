package rules

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/dorgrn/decloak/internal/parser"
	"github.com/odvcencio/gotreesitter"
)

type EngineConfig struct {
	Workers       int
	MaxBlankLines int
	Verbose       bool
	// Policy enables the capability/policy layer (POL-* rules): visible but
	// dangerous behavior rather than concealed content.
	Policy bool
}

const slowFileThreshold = 2 * time.Second

type Engine struct {
	registry *Registry
	cfg      EngineConfig
}

func NewEngine(reg *Registry, cfg EngineConfig) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.MaxBlankLines <= 0 {
		cfg.MaxBlankLines = 50
	}
	return &Engine{
		registry: reg,
		cfg:      cfg,
	}
}

// Run distributes discovered TargetFiles across a bounded pool of goroutines.
// Each worker owns dedicated pure-Go gotreesitter.Parser instances (avoiding lock contention).
func (e *Engine) Run(ctx context.Context, targets []model.TargetFile) ([]model.Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	jobs := make(chan model.TargetFile, len(targets))
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	var (
		mu          sync.Mutex
		allFindings []model.Finding
		wg          sync.WaitGroup
	)

	workerCount := e.cfg.Workers
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp := parser.NewWorkerParsers()

			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				started := time.Now()
				fileFindings, err := e.scanTarget(wp, target)
				if e.cfg.Verbose {
					if d := time.Since(started); d > slowFileThreshold {
						fmt.Fprintf(os.Stderr, "[decloak] slow: %s took %v\n", target.Path, d.Round(time.Millisecond))
					}
				}
				if err != nil {
					if e.cfg.Verbose {
						fmt.Fprintf(os.Stderr, "[decloak] error scanning %s: %v\n", target.Path, err)
					}
					continue
				}

				if len(fileFindings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, fileFindings...)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	sortFindings(allFindings)
	return allFindings, nil
}

func sortFindings(f []model.Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Severity != f[j].Severity {
			return f[i].Severity > f[j].Severity
		}
		if f[i].FilePath != f[j].FilePath {
			return f[i].FilePath < f[j].FilePath
		}
		return f[i].StartLine < f[j].StartLine
	})
}

func (e *Engine) scanTarget(wp *parser.WorkerParsers, target model.TargetFile) ([]model.Finding, error) {
	src, err := os.ReadFile(target.Path)
	if err != nil {
		return nil, err
	}
	return e.scanSource(wp, target, src)
}

// ScanSource scans in-memory content as if it were the file target.Path,
// for callers without a filesystem (the browser demo).
func (e *Engine) ScanSource(target model.TargetFile, src []byte) ([]model.Finding, error) {
	findings, err := e.scanSource(parser.NewWorkerParsers(), target, src)
	sortFindings(findings)
	return findings, err
}

func (e *Engine) scanSource(wp *parser.WorkerParsers, target model.TargetFile, src []byte) ([]model.Finding, error) {
	var findings []model.Finding

	// Minified bundles (vendored JS, browser extensions) are generated code:
	// slow to parse and not where agent instructions live. Lexical checks still
	// run so an encoded payload or hidden instruction inside one is caught.
	if target.Language != model.LangMarkdown && isMinified(src) {
		if e.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "[decloak] minified, AST rules skipped: %s\n", target.Path)
		}
		findings = append(findings, InspectInstructionText(target, target.Language, src)...)
		findings = append(findings, InspectDecodedPayloads(target, target.Language, src)...)
		if e.cfg.Policy {
			findings = append(findings, InspectPolicy(target, target.Language, src)...)
		}
		return dedupeFindings(dropShadowedInlineExec(findings)), nil
	}

	// 1. Parse primary file AST and run language-specific S-expression rules
	tree, lang, err := wp.Parse(target.Language, src)
	if err != nil {
		return nil, err
	}
	root := tree.RootNode()

	findings = append(findings, e.evalQueries(root, lang, src, target, target.Language, 0)...)
	findings = append(findings, e.evalMultiHopTaint(root, lang, src, target, target.Language, 0)...)
	if target.Language == model.LangShell {
		findings = append(findings, e.shellTaint(root, lang, src, target, 0)...)
	}
	findings = append(findings, InspectInstructionText(target, target.Language, src)...)
	findings = append(findings, InspectDecodedPayloads(target, target.Language, src)...)

	// 2. If Markdown: run raw lexical concealment checks AND extract embedded Python/JS code fences
	if target.Language == model.LangMarkdown {
		findings = append(findings, InspectRawMarkdown(target, src, e.cfg.MaxBlankLines)...)
		findings = append(findings, InspectSkillStructure(target, src)...)

		blocks, err := parser.ExtractEmbeddedCodeBlocks(root, lang, src)
		if err == nil {
			for _, block := range blocks {
				subTree, subLang, subErr := wp.Parse(block.Language, block.Content)
				if subErr != nil {
					continue
				}
				subFindings := e.evalQueries(
					subTree.RootNode(),
					subLang,
					block.Content,
					target,
					block.Language,
					block.BaseLineOffset,
				)
				subFindings = append(subFindings, e.evalMultiHopTaint(
					subTree.RootNode(),
					subLang,
					block.Content,
					target,
					block.Language,
					block.BaseLineOffset,
				)...)
				if block.Language == model.LangShell {
					subFindings = append(subFindings, e.shellTaint(subTree.RootNode(), subLang, block.Content, target, block.BaseLineOffset)...)
				}
				findings = append(findings, subFindings...)
			}
		}
	}

	if e.cfg.Policy {
		findings = append(findings, InspectPolicy(target, target.Language, src)...)
	}

	return dedupeFindings(dropShadowedInlineExec(findings)), nil
}

func (e *Engine) evalQueries(
	root *gotreesitter.Node,
	lang *gotreesitter.Language,
	src []byte,
	target model.TargetFile,
	ruleLang model.Language,
	baseLineOffset uint32,
) []model.Finding {
	compiledRules := e.registry.RulesForLanguage(ruleLang)
	var findings []model.Finding
	seen := make(map[string]struct{})

	for _, rule := range compiledRules {
		cursor := rule.Query.Exec(root, lang, src)
		for {
			match, ok := cursor.NextMatch()
			if !ok {
				break
			}

			for _, cap := range match.Captures {
				if cap.Name != "finding" {
					continue
				}
				start := cap.Node.StartPoint()
				end := cap.Node.EndPoint()
				snippet := oneLineSnippet(cap.Node.Text(src))

				key := fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d", rule.ID, start.Row, start.Column, end.Row, end.Column)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}

				findings = append(findings, model.Finding{
					RuleID:       rule.ID,
					Severity:     rule.Severity,
					SeverityName: rule.Severity.String(),
					Language:     ruleLang,
					FilePath:     target.Path,
					SourceOrigin: target.SourceOrigin,
					StartLine:    baseLineOffset + start.Row + 1,
					EndLine:      baseLineOffset + end.Row + 1,
					StartCol:     start.Column + 1,
					EndCol:       end.Column + 1,
					Message:      rule.Description,
					Snippet:      snippet,
					Remediation:  rule.Remediation,
				})
			}
		}
	}

	return findings
}

func oneLineSnippet(raw string) string {
	collapsed := strings.Join(strings.Fields(raw), " ")
	if len(collapsed) > 120 {
		return collapsed[:117] + "..."
	}
	return collapsed
}
