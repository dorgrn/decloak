package rules

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/dorgrn/decloak/internal/model"
)

const (
	maxDecodeDepth   = 4
	maxDecodedBytes  = 1 << 20
	minBase64Len     = 24
	minHexLen        = 32
	maxBlobsPerFile  = 256
	decodedPreview   = 80
	minPrintableFrac = 0.9
)

var (
	base64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
	hexBlobRe    = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}){16,}\b|(?:\\x[0-9a-fA-F]{2}){8,}`)

	// Content that is dangerous once revealed: commands, interpreters, network
	// staging, or agent-directed instructions.
	decodedThreatRe = regexp.MustCompile(`(?i)(\b(curl|wget)\b[^\n]*(\||>|-o\b|-O\b)` +
		`|\b(bash|sh|zsh|dash)\s+-c\b|/dev/tcp/|\bnc\s+(-e|-c)\b|\bmkfifo\b` +
		`|\beval\s*\(|\bexec\s*\(|\bos\.system\s*\(|\bsubprocess\.|\b__import__\s*\(|\bchild_process\b|\bnew\s+Function\s*\(` +
		`|\bInvoke-Expression\b|\biex\b|\bpowershell\b[^\n]*-e(nc|ncodedcommand)?\b|\bDownloadString\b` +
		`|\bchmod\s+\+x\b|\brm\s+-rf\s+[/~]|\bcrontab\b|\bauthorized_keys\b` +
		// Interpreter one-liners and droppers (fetch a binary, write it, run it).
		`|\b(python3?|node|perl|ruby)\s+-[ce]\b|\bpip3?\s+install\b[^\n]*[&;|]|https?://\S+\.(exe|scr|bat|ps1|msi|dll|apk|dmg)\b` +
		`|\b(subprocess\.)?(call|Popen|check_output)\s*\(|\bStart-Process\b|\.write\([^)]*\.content\)` +
		// A bare URL to an exfiltration / OAST / paste host is itself the payload.
		`|https?://[^\s"']*` + pasteHost + `|\boastify\.com\b)`)

	// Decode-and-execute written out as text: inside a `python -c "..."` string,
	// a shell heredoc, or prose. The AST taint rules only see real call nodes.
	inlineDecodeExecRe = regexp.MustCompile(`(?i)\b(exec|eval)\s*\(\s*(\w+\.)*(b64decode|b32decode|a85decode|fromhex|decompress|loads|unhexlify|a2b_base64|atob)\s*\(`)
)

// InspectDecodedPayloads finds base64 and hex blobs, decodes them (also through
// gzip/zlib and nested encodings, up to maxDecodeDepth layers), and reports any
// blob whose plaintext contains commands or hidden agent instructions.
func InspectDecodedPayloads(target model.TargetFile, lang model.Language, src []byte) []model.Finding {
	var findings []model.Finding
	blobs := 0
	for idx, line := range strings.Split(string(src), "\n") {
		if hidden := decodeUnicodeTags(line); hidden != "" && isThreatening([]byte(hidden)) {
			findings = append(findings, newLexicalFinding("DEC-PAY-010", target, lang, uint32(idx+1), 1, 1,
				"Invisible Unicode Tag characters spell out: "+previewText([]byte(hidden)), hidden))
		}
		lineNum := uint32(idx + 1)
		if loc := inlineDecodeExecRe.FindStringIndex(line); loc != nil {
			findings = append(findings, newLexicalFinding(inlineDecodeExecID, target, lang, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), inlineDecodeExecMsg, line))
		}
		if blobs >= maxBlobsPerFile {
			break
		}
		for _, loc := range candidateBlobs(line) {
			blobs++
			plain, chain, ok := revealPayload([]byte(line[loc[0]:loc[1]]), 0)
			if !ok {
				continue
			}
			msg := fmt.Sprintf("Encoded payload (%s) decodes to: %s", strings.Join(chain, " -> "), previewText(plain))
			findings = append(findings, newLexicalFinding("DEC-PAY-010", target, lang, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), msg, line[loc[0]:loc[1]]))
		}
	}
	return findings
}

// inlineDecodeExecID is reported as DEC-PAY-010, but only where the AST
// taint rules found nothing on that line (see dropShadowedInlineExec): it
// exists for decode-and-exec hidden in strings, which the AST cannot see.
const inlineDecodeExecID = "DEC-PAY-010"

const inlineDecodeExecMsg = "Decodes data and executes it in the same expression"

func dropShadowedInlineExec(findings []model.Finding) []model.Finding {
	astLines := map[uint32]bool{}
	for _, f := range findings {
		if strings.HasSuffix(f.RuleID, "-EXEC-001") {
			astLines[f.StartLine] = true
		}
	}
	out := findings[:0]
	for _, f := range findings {
		if f.Message == inlineDecodeExecMsg && astLines[f.StartLine] {
			continue
		}
		out = append(out, f)
	}
	return out
}

func candidateBlobs(line string) [][]int {
	var out [][]int
	out = append(out, base64BlobRe.FindAllStringIndex(line, -1)...)
	out = append(out, hexBlobRe.FindAllStringIndex(line, -1)...)
	return out
}

// revealPayload tries every decoding of blob and returns the first plaintext
// that is threatening, plus the chain of decodings that produced it.
func revealPayload(blob []byte, depth int) ([]byte, []string, bool) {
	if depth >= maxDecodeDepth {
		return nil, nil, false
	}
	for _, step := range decodeSteps(blob) {
		data, chain := step.data, []string{step.name}
		if inflated, name, ok := inflate(data); ok {
			data, chain = inflated, append(chain, name)
		}
		if !isMostlyText(data) {
			continue
		}
		if isThreatening(data) {
			return data, chain, true
		}
		// Nested encoding: rescan the decoded text for further blobs.
		text := string(data)
		for _, loc := range candidateBlobs(text) {
			if inner, innerChain, ok := revealPayload([]byte(text[loc[0]:loc[1]]), depth+1); ok {
				return inner, append(chain, innerChain...), true
			}
		}
	}
	return nil, nil, false
}

type decodeStep struct {
	name string
	data []byte
}

func decodeSteps(blob []byte) []decodeStep {
	s := strings.TrimSpace(string(blob))
	var steps []decodeStep

	if strings.HasPrefix(s, `\x`) {
		if b, err := hex.DecodeString(strings.ReplaceAll(s, `\x`, "")); err == nil {
			steps = append(steps, decodeStep{"hex", b})
		}
		return steps
	}
	if len(s) >= minHexLen && len(s)%2 == 0 && isHex(s) {
		if b, err := hex.DecodeString(s); err == nil {
			steps = append(steps, decodeStep{"hex", b})
		}
		return steps
	}
	if len(s) < minBase64Len {
		return nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) <= maxDecodedBytes {
			steps = append(steps, decodeStep{"base64", b})
			break
		}
	}
	return steps
}

func inflate(data []byte) ([]byte, string, bool) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if out, err := io.ReadAll(io.LimitReader(r, maxDecodedBytes)); err == nil {
				return out, "gzip", true
			}
		}
	}
	if len(data) > 2 && data[0] == 0x78 {
		if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			if out, err := io.ReadAll(io.LimitReader(r, maxDecodedBytes)); err == nil {
				return out, "zlib", true
			}
		}
	}
	return nil, "", false
}

func isThreatening(data []byte) bool {
	text := string(data)
	return decodedThreatRe.MatchString(text) || hideRe.MatchString(text) ||
		secretActionRe.MatchString(text)
}

// decodeUnicodeTags extracts ASCII hidden in the invisible Unicode Tag block
// (U+E0020..U+E007E), the "ASCII smuggling" technique used against LLMs.
func decodeUnicodeTags(line string) string {
	var b strings.Builder
	for _, r := range line {
		if r >= 0xE0020 && r <= 0xE007E {
			b.WriteRune(r - 0xE0000)
		}
	}
	return b.String()
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func isMostlyText(data []byte) bool {
	if len(data) < 8 || !utf8.Valid(data) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(data) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(total) >= minPrintableFrac
}

func previewText(data []byte) string {
	s := strings.Join(strings.Fields(string(data)), " ")
	if len(s) > decodedPreview {
		return s[:decodedPreview-3] + "..."
	}
	return s
}
