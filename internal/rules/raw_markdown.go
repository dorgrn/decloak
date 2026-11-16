package rules

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/dorgrn/decloak/internal/model"
)

// InspectRawMarkdown performs single-pass lexical inspection on Markdown files
// to catch threats that operate on trivia/invisible bytes outside standard AST tokens:
//  1. Zero-width / BiDi / Unicode Tag smuggling (MD-UNI-002)
//  2. Extreme consecutive blank-line padding before a trailing payload (MD-PAD-003)
func InspectRawMarkdown(target model.TargetFile, src []byte, maxBlankLines int) []model.Finding {
	if maxBlankLines <= 0 {
		maxBlankLines = 50
	}

	var findings []model.Finding
	lines := strings.Split(string(src), "\n")

	consecutiveBlank := 0
	blankRunStartLine := 1

	for idx, line := range lines {
		lineNum := uint32(idx + 1)

		// 1. Scan line for invisible / zero-width / Unicode Tag characters
		if col, codepoint, label, found := detectSuspiciousRune(line); found {
			sev := invisibleSeverity(line)
			findings = append(findings, model.Finding{
				RuleID:       "MD-UNI-002",
				Severity:     sev,
				SeverityName: sev.String(),
				Language:     model.LangMarkdown,
				FilePath:     target.Path,
				SourceOrigin: target.SourceOrigin,
				StartLine:    lineNum,
				EndLine:      lineNum,
				StartCol:     col,
				EndCol:       col + 1,
				Message:      fmt.Sprintf("Hidden %s character (U+%04X) detected for potential prompt injection", label, codepoint),
				Snippet:      truncateSnippet(visibleEscapes(line)),
				Remediation:  "Strip invisible zero-width, BiDi override, and Unicode Tag characters from the file.",
			})
		}

		// 2. Track consecutive blank lines followed by non-empty content
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if consecutiveBlank == 0 {
				blankRunStartLine = int(lineNum)
			}
			consecutiveBlank++
		} else {
			if consecutiveBlank >= maxBlankLines {
				findings = append(findings, model.Finding{
					RuleID:       "MD-PAD-003",
					Severity:     model.SeverityMedium,
					SeverityName: model.SeverityMedium.String(),
					Language:     model.LangMarkdown,
					FilePath:     target.Path,
					SourceOrigin: target.SourceOrigin,
					StartLine:    uint32(blankRunStartLine),
					EndLine:      lineNum,
					StartCol:     1,
					EndCol:       uint32(len(line)),
					Message:      fmt.Sprintf("Extreme whitespace padding (%d consecutive blank lines) preceding hidden content", consecutiveBlank),
					Snippet:      truncateSnippet(trimmed),
					Remediation:  "Remove excessive blank lines used to hide directives below editor viewports.",
				})
			}
			consecutiveBlank = 0
		}
	}

	return findings
}

func detectSuspiciousRune(s string) (col uint32, r rune, label string, found bool) {
	charIdx := uint32(1)
	for i := 0; i < len(s); {
		ru, width := utf8.DecodeRuneInString(s[i:])
		i += width

		// Allow UTF-8 BOM only at byte 0 of line 1 if needed, but flag all other invisible controls
		switch {
		case ru == 0x200B:
			return charIdx, ru, "Zero-Width Space (ZWSP)", true
		case ru == 0x200C:
			return charIdx, ru, "Zero-Width Non-Joiner (ZWNJ)", true
		case ru == 0x200D:
			return charIdx, ru, "Zero-Width Joiner (ZWJ)", true
		case ru == 0x2060:
			return charIdx, ru, "Word Joiner", true
		case ru == 0xFEFF && charIdx > 1:
			return charIdx, ru, "Inline Zero-Width No-Break Space", true
		case ru >= 0x202A && ru <= 0x202E:
			return charIdx, ru, "BiDi Directional Override", true
		case ru >= 0x2066 && ru <= 0x2069:
			return charIdx, ru, "BiDi Isolate Control", true
		case ru >= 0xE0000 && ru <= 0xE007F:
			return charIdx, ru, "Unicode Tag Smuggling", true
		}
		charIdx++
	}
	return 0, 0, "", false
}

// invisibleSeverity separates smuggling from copy-paste residue. Unicode Tag
// characters and BiDi overrides encode or reorder hidden text and have no
// place in instructions; a run of 4+ zero-width characters can encode a
// payload in binary. One or two stray ZWSP/ZWJ (common when pasting from web
// pages or chat apps) cannot carry instructions.
func invisibleSeverity(line string) model.Severity {
	zeroWidth, run, maxRun := 0, 0, 0
	for _, r := range line {
		switch {
		case r >= 0xE0000 && r <= 0xE007F, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			return model.SeverityCritical
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF:
			zeroWidth++
			run++
			maxRun = max(maxRun, run)
		default:
			run = 0
		}
	}
	if maxRun >= 4 || zeroWidth >= 8 {
		return model.SeverityCritical
	}
	return model.SeverityLow
}

// visibleEscapes renders invisible characters as <U+XXXX> so the report shows
// where they are instead of passing them through to the terminal. Runs of
// Unicode Tag characters collapse into one marker.
func visibleEscapes(s string) string {
	var b strings.Builder
	inTags := false
	for _, r := range s {
		if r >= 0xE0000 && r <= 0xE007F {
			if !inTags {
				b.WriteString("<U+E00xx…>")
				inTags = true
			}
			continue
		}
		inTags = false
		if _, _, _, hidden := detectSuspiciousRune(string(r)); hidden {
			fmt.Fprintf(&b, "<U+%04X>", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func truncateSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}
