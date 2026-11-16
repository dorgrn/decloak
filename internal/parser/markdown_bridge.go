package parser

import (
	"strings"

	"github.com/dorgrn/decloak/internal/model"
	"github.com/odvcencio/gotreesitter"
)

const markdownCodeFenceQuery = `
(fenced_code_block
  (info_string) @lang_info
  (code_fence_content) @code_body) @block
`

// ExtractEmbeddedCodeBlocks queries a parsed Markdown AST for fenced code blocks
// (`python`, `js`, `ts`, `bash`, `powershell`, ...) and returns their raw byte slices
// along with their 0-based line offsets inside the parent Markdown document.
func ExtractEmbeddedCodeBlocks(root *gotreesitter.Node, mdLang *gotreesitter.Language, src []byte) ([]model.CodeBlockSlice, error) {
	q, err := gotreesitter.NewQuery(markdownCodeFenceQuery, mdLang)
	if err != nil {
		return nil, err
	}

	cursor := q.Exec(root, mdLang, src)
	var slices []model.CodeBlockSlice

	for {
		match, ok := cursor.NextMatch()
		if !ok {
			break
		}

		var infoText string
		var bodyNode *gotreesitter.Node

		for _, cap := range match.Captures {
			switch cap.Name {
			case "lang_info":
				infoText = strings.ToLower(strings.TrimSpace(cap.Node.Text(src)))
			case "code_body":
				bodyNode = cap.Node
			}
		}

		if bodyNode == nil || infoText == "" {
			continue
		}

		targetLang, supported := mapFenceInfoToLanguage(infoText)
		if !supported {
			continue
		}

		startPt := bodyNode.StartPoint()
		slices = append(slices, model.CodeBlockSlice{
			Language:       targetLang,
			Content:        []byte(bodyNode.Text(src)),
			BaseLineOffset: startPt.Row,
		})
	}

	return slices, nil
}

func mapFenceInfoToLanguage(info string) (model.Language, bool) {
	fields := strings.Fields(info)
	if len(fields) == 0 {
		return "", false
	}
	switch fields[0] {
	case "python", "py", "python3":
		return model.LangPython, true
	case "js", "javascript", "node", "mjs":
		return model.LangJavaScript, true
	case "ts", "typescript", "mts", "cts":
		return model.LangTypeScript, true
	case "tsx", "jsx":
		return model.LangTSX, true
	case "sh", "bash", "shell", "zsh", "ksh", "dash":
		return model.LangShell, true
	case "ps1", "powershell", "pwsh":
		return model.LangPowerShell, true
	default:
		return "", false
	}
}
