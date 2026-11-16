package parser

import (
	"fmt"
	"sync"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars/bash"
	"github.com/odvcencio/gotreesitter/grammars/javascript"
	"github.com/odvcencio/gotreesitter/grammars/markdown"
	"github.com/odvcencio/gotreesitter/grammars/powershell"
	"github.com/odvcencio/gotreesitter/grammars/python"
	"github.com/odvcencio/gotreesitter/grammars/tsx"
	"github.com/odvcencio/gotreesitter/grammars/typescript"
)

var (
	langOnce sync.Once
	mdLang   *gotreesitter.Language
	pyLang   *gotreesitter.Language
	jsLang   *gotreesitter.Language
	tsLang   *gotreesitter.Language
	tsxLang  *gotreesitter.Language
	shLang   *gotreesitter.Language
	psLang   *gotreesitter.Language
)

func initLanguages() {
	langOnce.Do(func() {
		mdLang = markdown.Language()
		pyLang = python.Language()
		jsLang = javascript.Language()
		tsLang = typescript.Language()
		tsxLang = tsx.Language()
		shLang = bash.Language()
		psLang = powershell.Language()
	})
}

// LanguageFor returns the singleton pure-Go gotreesitter Language for the given model.Language.
func LanguageFor(lang model.Language) (*gotreesitter.Language, error) {
	initLanguages()
	switch lang {
	case model.LangMarkdown:
		return mdLang, nil
	case model.LangPython:
		return pyLang, nil
	case model.LangJavaScript:
		return jsLang, nil
	case model.LangTypeScript:
		return tsLang, nil
	case model.LangTSX:
		return tsxLang, nil
	case model.LangShell:
		return shLang, nil
	case model.LangPowerShell:
		return psLang, nil
	default:
		return nil, fmt.Errorf("unsupported grammar language: %s", lang)
	}
}

// WorkerParsers holds dedicated, non-concurrent Parser instances for a single worker goroutine.
type WorkerParsers struct {
	mdParser  *gotreesitter.Parser
	pyParser  *gotreesitter.Parser
	jsParser  *gotreesitter.Parser
	tsParser  *gotreesitter.Parser
	tsxParser *gotreesitter.Parser
	shParser  *gotreesitter.Parser
	psParser  *gotreesitter.Parser
}

// NewWorkerParsers allocates reusable pure-Go parsers for Markdown, Python,
// JavaScript, TypeScript, shell, and PowerShell.
func NewWorkerParsers() *WorkerParsers {
	initLanguages()
	return &WorkerParsers{
		mdParser:  gotreesitter.NewParser(mdLang),
		pyParser:  gotreesitter.NewParser(pyLang),
		jsParser:  gotreesitter.NewParser(jsLang),
		tsParser:  gotreesitter.NewParser(tsLang),
		tsxParser: gotreesitter.NewParser(tsxLang),
		shParser:  gotreesitter.NewParser(shLang),
		psParser:  gotreesitter.NewParser(psLang),
	}
}

// Parse parses src using the worker's dedicated parser for lang.
func (wp *WorkerParsers) Parse(lang model.Language, src []byte) (*gotreesitter.Tree, *gotreesitter.Language, error) {
	switch lang {
	case model.LangMarkdown:
		tree, err := wp.mdParser.Parse(src)
		return tree, mdLang, err
	case model.LangPython:
		tree, err := wp.pyParser.Parse(src)
		return tree, pyLang, err
	case model.LangJavaScript:
		tree, err := wp.jsParser.Parse(src)
		return tree, jsLang, err
	case model.LangTypeScript:
		tree, err := wp.tsParser.Parse(src)
		return tree, tsLang, err
	case model.LangTSX:
		tree, err := wp.tsxParser.Parse(src)
		return tree, tsxLang, err
	case model.LangShell:
		tree, err := wp.shParser.Parse(src)
		return tree, shLang, err
	case model.LangPowerShell:
		tree, err := wp.psParser.Parse(src)
		return tree, psLang, err
	default:
		return nil, nil, fmt.Errorf("no parser registered for language %q", lang)
	}
}
