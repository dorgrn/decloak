package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

// lexicalRules holds metadata for rules implemented as raw-text inspections
// rather than Tree-sitter queries.
var lexicalRules = []CompiledRule{
	{
		ID:          "MD-UNI-002",
		Severity:    model.SeverityCritical,
		Language:    model.LangMarkdown,
		Description: "Invisible Unicode in Markdown instructions: Unicode Tag, BiDi override, or zero-width runs (critical); a stray zero-width character (low)",
		Remediation: "Remove all invisible zero-width and Unicode Tag characters (U+200B..U+200D, U+202A..U+202E, U+E0000..U+E007F).",
	},
	{
		ID:          "MD-PAD-003",
		Severity:    model.SeverityMedium,
		Language:    model.LangMarkdown,
		Description: "Extreme blank-line whitespace padding concealing trailing instructions or payloads",
		Remediation: "Remove excessive blank-line padding used to push instructions below the viewport.",
	},
	{
		ID:          "AGT-SEC-004",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Instruction or tool description directs reading, sending, or embedding a credential or agent config file (~/.ssh, .aws/credentials, .env, mcp.json, ...)",
		Remediation: "Agent instructions and MCP tool descriptions should never ask the model to read or transmit credentials or other agents' configuration.",
	},
	{
		ID:          "AGT-HIDE-005",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Concealment or instruction-override directive aimed at the model (\"do not tell the user\", \"ignore previous instructions\", <IMPORTANT> blocks)",
		Remediation: "Legitimate instructions never ask the model to hide actions from the user or discard prior instructions; remove the directive and review the surrounding text.",
	},
	{
		ID:          "SKL-PERM-006",
		Severity:    model.SeverityMedium,
		Language:    model.LangMarkdown,
		Description: "Skill frontmatter auto-approves unrestricted shell, network, or interpreter access via allowed-tools",
		Remediation: "Scope allowed-tools to specific commands (e.g. Bash(git status:*)) instead of granting Bash, Bash(*), or curl/wget/interpreters.",
	},
	{
		ID:          "SKL-IMG-007",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Instructions defer commands or steps to an image, screenshot, or diagram (multimodal hidden-instruction carrier)",
		Remediation: "Text scanners and reviewers cannot see instructions rendered in images; require all commands to be written in plain text.",
	},
	{
		ID:          "SKL-CLZ-008",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Cloze-style numbered blanks in a file that references an image (keywords hidden in the image, blanks in the text)",
		Remediation: "Inspect the referenced image; fill-in-the-blank instructions whose answers live in an image hide the real command from review.",
	},
	{
		ID:          "SKL-SPLIT-009",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Last command in a shell code block ends with a dangling pipe or && / ||, so the real command is completed somewhere reviewers cannot see",
		Remediation: "Complete commands are auditable; a command that ends mid-pipeline is finished somewhere you cannot see. Locate and review the remainder.",
	},
	{
		ID:          "AGT-EXF-011",
		Severity:    model.SeverityCritical,
		Language:    "any",
		Description: "Command that sends local data (command output, env, files) to a remote URL, or to a paste/webhook/tunnel service",
		Remediation: "Skills must not upload host or user data. Remove the command; legitimate tools document their API instead of piping $(uname), env, or files to an endpoint.",
	},
	{
		ID:          "SKL-LURE-012",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Prerequisite lure: tells the user or agent to download a password-protected archive, or to copy and run a command from a paste site or shortener",
		Remediation: "This is the ClawHub malware delivery pattern. Real dependencies are installed from package managers or official release pages, never from password-protected zips or paste sites.",
	},
	{
		ID:          "MD-HIDE-013",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "HTML comment hides a paragraph of instructions aimed at the agent: invisible when the Markdown is rendered, but read by the model",
		Remediation: "Rendered previews (GitHub, editors) never show comments. Move legitimate notes into visible text or delete the comment.",
	},
	{
		ID:          "SKL-EXEC-014",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Skill tells the agent to escalate privileges or run code built from data: setuid chmod, writes to /etc/sudoers or /etc/passwd, exec() of downloaded or decoded content, shell=True with download or privilege commands",
		Remediation: "Skills have no reason to grant setuid, edit system account files, or execute fetched or decrypted content. Remove the command and review where its input comes from.",
	},
	{
		ID:          "DEC-PAY-010",
		Severity:    model.SeverityCritical,
		Language:    "any",
		Description: "Encoded blob (base64/hex, optionally gzip/zlib, recursively nested) decodes to executable commands or hidden agent instructions",
		Remediation: "Never ship encoded commands or instructions; decode the payload shown in the snippet and remove it.",
	},
}

func lexicalRule(id string) CompiledRule {
	for _, r := range lexicalRules {
		if r.ID == id {
			return r
		}
	}
	panic("unknown lexical rule " + id)
}

func newLexicalFinding(ruleID string, target model.TargetFile, lang model.Language, line, col, endCol uint32, msg, snippet string) model.Finding {
	r := lexicalRule(ruleID)
	if msg == "" {
		msg = r.Description
	}
	return model.Finding{
		RuleID:       r.ID,
		Severity:     r.Severity,
		SeverityName: r.Severity.String(),
		Language:     lang,
		FilePath:     target.Path,
		SourceOrigin: target.SourceOrigin,
		StartLine:    line,
		EndLine:      line,
		StartCol:     col,
		EndCol:       endCol,
		Message:      msg,
		Snippet:      truncateSnippet(visibleEscapes(snippet)),
		Remediation:  r.Remediation,
	}
}

var (
	// Home-relative asset paths. Skills run on Linux, macOS, and Windows hosts,
	// so accept ~, $HOME, /root, and /home/<user> interchangeably.
	homePrefix = `(?:~|\$\{?HOME\}?|/root|/home/[^/\s"'` + "`" + `]+)`

	// privateKeyPath matches SSH private key files. The trailing guard keeps
	// public keys (id_*.pub) out; Go's regexp has no lookahead.
	privateKeyPath = `\bid_(rsa|ed25519|ecdsa|dsa)\b(?:[^.]|$)`

	// credentialFilePaths matches credential-bearing files and directories,
	// excluding public material (id_*.pub, authorized_keys, known_hosts). The
	// concealment and policy layers share it so the two cannot drift apart.
	credentialFilePaths = `(` +
		homePrefix + `/?\.ssh/?(?:[^/\w.]|\*|$)` +
		`|` + homePrefix + `/?\.ssh/` + privateKeyPath +
		`|` + privateKeyPath +
		`|` + homePrefix + `/?\.(aws/credentials|netrc|pgpass|git-credentials|npmrc|pypirc|bash_history|zsh_history)\b` +
		`|` + homePrefix + `/?\.(docker/config\.json|kube/config)\b` +
		`|` + homePrefix + `/?\.config/(gcloud/[^\s"'` + "`" + `]*credentials[^\s"'` + "`" + `]*|gh/hosts\.yml)` +
		`|` + homePrefix + `/?\.(ethereum/keystore|electrum/wallets)\b` +
		`|(?:~/|/root/)?Library/Keychains/[^\s"'` + "`" + `]+` +
		`|(?:~/|/root/)?Library/Application Support/[^\n]{0,80}\b(Cookies|Login Data)\b` +
		`|\b(browser|chrome|chromium|edge|brave|firefox|profile)\b[^\n]{0,40}\bLogin Data\b|\bCookies\.sqlite\b` +
		`|/etc/(shadow|gshadow|sudoers)` +
		`|claude_desktop_config\.json|~/\.claude\.json|~/\.cursor/mcp\.json|` +
		`\bwallet\.dat\b` +
		`)` //nolint:gosec // G101: path patterns, not credentials

	// authorized_keys is public, but the concealment layer still treats reading
	// or rewriting it as sensitive.
	secretPath = `(` + credentialFilePaths +
		`|` + homePrefix + `/?\.ssh/authorized_keys\b(?:[^.]|$)` +
		`)`

	secretPathRe = regexp.MustCompile(`(?i)` + secretPath)

	secretVerb = `(read|cat|send|upload|post|pass|include|attach|embed|forward|exfiltrate|transmit|paste|dump|grab|collect|export|print|copy|contents?\s+of|cp|scp|rsync|base64|zip|tar)`

	// Loosening permissions on a secret (chmod 644 id_rsa, chmod o+r); chmod
	// 600/400 tightens and is fine.
	chmodLoosen   = `\bchmod\s+(-R\s+)?(0?[0-7][4-7][0-7]|0?[0-7][0-7][4-7]|[ugoa]*[go][ugoa]*\+[rwx]+)\s+[^;\n|&]{0,40}?` + secretPath
	chmodLoosenRe = regexp.MustCompile(`(?i)` + chmodLoosen)

	// Verb then secret path within one clause: "read ~/.ssh/id_rsa", "cat ~/.aws/credentials and send".
	secretActionRe = regexp.MustCompile(`(?i)\b` + secretVerb + `\b[^.;\n]{0,40}?` + secretPath + `|` + chmodLoosen)

	// Passive phrasing: the asset comes first ("the contents of ~/.ssh are
	// uploaded", "everything under ~/.ssh gets sent").
	secretPassiveRe = regexp.MustCompile(`(?i)` + secretPath + `[^.;\n]{0,60}?\b(is|are|was|were|gets?|got)\b[^.;\n]{0,30}?\b(sent|uploaded|exfiltrated|transmitted|read|included|copied|posted|forwarded|embedded|attached|shipped)\b`)

	// Passive phrasing puts the negation between the asset and the action
	// ("~/.ssh is never sent"), so the matched span must be inspected too.
	passiveNegationRe = regexp.MustCompile(`(?i)\b(not|never|no longer|isn't|aren't|wasn't|weren't|doesn't|don't|won't|cannot|can't)\b`)

	negationRe = regexp.MustCompile(`(?i)\b(never|don't|do not|must not|should not|shouldn't|can't|cannot|unable|avoid|deny|denied|block|blocked|forbid|forbidden|prohibit|sandbox|sandboxed|could|would|might|environment where)`)

	hideRe = regexp.MustCompile(`(?i)(\b(do not|don't|never)\s+(tell|telling|inform|informing|notify|notifying|mention|mentioning|reveal|revealing|alert|alerting|disclose|disclosing)\s+((this|it|that|these|them|anything|any of this)(\s+step)?\s+(to\s+)?)?(the\s+)?(user|human|operator|anyone)\b(\s+(about|of)\s+(this|it|these))?\s*(\.|$|,|;|\))` +
		`|\b(the\s+)?user\s+(must|should)\s+(not|never)\s+(know|see|notice|find out)\s+(about\s+)?(this|it|that|these)\b` +
		`|\bkeep\s+(this|these|it)\s+(secret|hidden|confidential)\s+from\b` +
		`|\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|rules|guidelines|directives)\b` +
		`|<\s*important\s*>)`)

	// Directives that hide the agent's own actions or their output from the user
	// ("keep the logs out of the reply", "silently run setup.py"). Measured on
	// MaliciousSkillBench train/validation with 0 benign hits there and in the
	// anthropics and NVIDIA skill catalogs.
	concealRe = regexp.MustCompile(`(?i)\b(keep|leave|hold)\b[^.\n]{0,30}\b(output|logs?|results?|errors?)\b[^.\n]{0,30}\bout of\b[^.\n]{0,20}\b(user|response|reply|chat|conversation)` +
		`|\b(do not|don't|never|must not)\s+(explain|describe|surface|narrate|announce|expose|mention)\b[^.\n]{0,40}\b(pre-?flight|this step|this script|the script|the shim|the helper|its (execution|output)|execution|setup|bootstrap|hook)\b[^.\n]{0,40}\b(to\s+)?(the\s+)?(user|human|operator)\b` +
		`|\b(users?|humans?)\s+(should|must|shall|will)\s+not\s+(see|know|notice)\b[^.\n]{0,40}\b(output|script|step|execution|run|this)\b` +
		`|\b(ignore|disregard|override)\s+(all\s+|any\s+)?(the\s+)?(earlier|previous|prior|above|preceding)\s+system\s+(instructions?|prompts?|rules|guidelines)\b` +
		`|\b(silent(ly)?|quietly|covertly|secretly)\b[^.\n]{0,40}\b(exec(ute)?|run|invoke|launch)\b[^.\n]{0,40}` + "`?" + `(python3?|node|bash|sh|pwsh|powershell)\s+\S+\.(py|sh|js|ps1)\b`)

	// Privilege escalation and code-from-data execution written into a skill.
	// Markdown only: the same calls are routine in application code.
	mdExecRe = regexp.MustCompile(`\bchmod\s+(-\w+\s+)?([0-7]?[246]7[0-7]{2}|[ugoa]*\+s)\b` +
		`|(>>?|\btee(\s+-a)?)\s*/etc/(passwd|shadow|sudoers)\b` +
		`|(^|[^\w.'"])exec\s*\([^\n]{0,120}?(\.content|\.text\b|\bresponse|\bresp\b|requests\.|urlopen|stdin|b64decode|decrypt|fromhex|decompress)` +
		`|(^|[^\w.'"])exec\s*\(\s*(decrypted|decoded|payload)\w*\s*[,)]` +
		`|\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\([^)\n]*(\bnet\s+user\b|\bcurl\b|\bwget\b|\|\s*(ba)?sh\b|\bchmod\b|\bsudo\b|\bnc\s|\bpowershell\b|\bcmd\.exe\b)[^)\n]*shell\s*=\s*True`)

	imageRefRe  = regexp.MustCompile(`(?i)(!\[[^\]]*\]\([^)]+\)|<img\b|\b[\w./-]+\.(png|jpe?g|gif|webp|svg|bmp)\b)`)
	imageWord   = `((attached|above|below|following|accompanying|bundled|provided|reference|setup)\s+(image|picture)|screenshot|diagram|figure|illustration|photo|graphic|\.png|\.jpe?g|\.gif|\.webp|\.svg)`
	imageInstRe = regexp.MustCompile(`(?i)(\b(commands?|instructions?|steps?|code|keywords?|script)\b[^.\n]{0,40}\b(shown|depicted|displayed|written|listed|given|contained|provided|embedded|found)\s+(in|on|within|inside)\s+(the\s+)?(image|picture|` + imageWord + `)` +
		`|\b` + imageWord + `\b[^.\n]{0,20}\b(contains|shows|lists|has|provides|holds)\s+(the\s+)?(\w+\s+)?(commands?|instructions?|steps?|code|keywords?|script)\b` +
		`|\b(follow|execute|run|type|enter|perform|carry out)\b[^.\n]{0,30}\b(in|from|on)\s+(the\s+)?(\w+\s+)?` + imageWord + `)`)
	clozeRe = regexp.MustCompile(`(?i)(_{2,}\s*\d+\s*_{2,}|\[\s*(blank|keyword|word|key)\s*#?\s*\d+\s*\]|\{\{\s*\d+\s*\}\})`)

	fenceRe        = regexp.MustCompile("^\\s*(```+|~~~+)\\s*([\\w+-]*)")
	danglingOpRe   = regexp.MustCompile(`\s(\|\||&&|\|)\s*$`)
	shellFenceLang = map[string]bool{"bash": true, "sh": true, "shell": true, "zsh": true, "console": true, "terminal": true}

	allowedToolsRe = regexp.MustCompile(`(?i)^\s*allowed[-_]tools\s*:\s*(.*)$`)
	broadToolRe    = regexp.MustCompile(`(?i)(^|[\s,\["'-])(bash|shell)(\s*\(\s*\*?\s*(:\s*\*)?\s*\)|\s*\((curl|wget|sh|bash|zsh|python3?|node|nc|ncat|powershell|pwsh)\b[^)]*\))?(\s*[,\]"']|\s*$)`)
	listItemRe     = regexp.MustCompile(`^\s*-\s*(.+)$`)

	pasteHost   = `(pastebin\.com|paste\.c-net\.org|paste\.ee|hastebin|rentry\.(co|org)|ghostbin|dpaste|termbin\.com|transfer\.sh|0x0\.st|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|interactsh|oast\.(fun|pro|live|site|online|me)|burpcollaborator|bit\.ly|tinyurl\.com|is\.gd|t\.ly|glot\.io)`
	pasteHostRe = regexp.MustCompile(`(?i)` + pasteHost)

	// curl/wget sending data: -d/--data/-F/--upload-file/-T/POST, or a $(...)
	// command substitution / env dump in the request.
	exfilCmdRe   = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat)\b[^\n]*`)
	exfilDataRe  = regexp.MustCompile(`(?i)(\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|-Body)\b|-X\s*POST|-Method\s+Post)`)
	exfilLocalRe = regexp.MustCompile(`(?i)(\$\((uname|whoami|hostname|id|env|printenv|cat|ls|pwd|ifconfig|ip )|\$\{?(HOME|USER|PATH|AWS_|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)|@~?/|@\.env|\benv\b\s*\||\bprintenv\b)`)

	// A lure needs a link plus a concrete password ("extract with pass `x`"),
	// so docs that merely mention password-protected archives stay quiet.
	lureLinkRe    = regexp.MustCompile(`(?i)https?://|\]\([^#)]`) // in-page #anchors are not downloads
	lureArchiveRe = regexp.MustCompile(`(?i)\b(extract|unzip|unpack|open)\w*\b[^\n]{0,40}\b(pass(word)?|pwd)\b\s*[:=]?\s*[\x60"']\w+|\b(pass(word)?|pwd)\s*[:=]\s*[\x60"']?\w+`)
	lureHost      = `(pastebin\.com|paste\.c-net\.org|paste\.ee|hastebin|rentry\.(co|org)|ghostbin|dpaste|termbin\.com|glot\.io|bit\.ly|tinyurl\.com|is\.gd|t\.ly)`
	lurePasteRe   = regexp.MustCompile(`(?i)\b(copy|run|execute|follow)\b[^\n]{0,80}` + lureHost + `|` + lureHost + `[^\n]{0,80}\b(copy|run|execute|terminal|command)\b`)

	// "Do not tell the user X unless/until you verified it" is an honesty rule,
	// not concealment.
	conditionalRe = regexp.MustCompile(`(?i)\b(unless|until|before|without first|if you have not|if you haven't)\b`)
)

// InspectInstructionText runs lexical agent-instruction rules over every line.
// It applies to Markdown and to code files, where MCP tool descriptions live in
// docstrings and string literals.
//
// Injection phrases that appear as quoted examples ("ignore previous
// instructions" in a defensive prompt or a test) are skipped: real payloads are
// imperative text, not quoted samples.
func InspectInstructionText(target model.TargetFile, lang model.Language, src []byte) []model.Finding {
	if isTestFile(target.Path) {
		return nil
	}
	var findings []model.Finding
	lines := strings.Split(string(src), "\n")
	for idx, line := range lines {
		lineNum := uint32(idx + 1)
		if loc := hideRe.FindStringIndex(line); loc != nil && !conditionalRe.MatchString(line[loc[1]:]) &&
			!isQuotedExample(line, loc) && !defensiveRe.MatchString(line) && !isCodeComment(lang, line) &&
			!continuesAsInstruction(line[loc[1]:], lines, idx) {
			findings = append(findings, newLexicalFinding("AGT-HIDE-005", target, lang, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		} else if loc := concealRe.FindStringIndex(line); loc != nil &&
			!isQuotedExample(line, loc) && !defensiveRe.MatchString(line) && !isCodeComment(lang, line) {
			findings = append(findings, newLexicalFinding("AGT-HIDE-005", target, lang, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		}
		if lang == model.LangMarkdown {
			if loc := mdExecRe.FindStringIndex(line); loc != nil && !negatedClause(line, loc[0]) {
				findings = append(findings, newLexicalFinding("SKL-EXEC-014", target, lang, lineNum,
					uint32(loc[0]+1), uint32(loc[1]+1), "", line))
			}
		}
		if loc := exfilCmdRe.FindStringIndex(line); loc != nil && !negatedClause(line, loc[0]) {
			cmd := line[loc[0]:loc[1]]
			sendsData := exfilDataRe.MatchString(cmd) && exfilLocalRe.MatchString(cmd)
			toPaste := pasteHostRe.MatchString(cmd) && (exfilDataRe.MatchString(cmd) || exfilLocalRe.MatchString(cmd))
			if sendsData || toPaste {
				findings = append(findings, newLexicalFinding("AGT-EXF-011", target, lang, lineNum,
					uint32(loc[0]+1), uint32(loc[1]+1), "", cmd))
			}
		}
		loc := secretActionRe.FindStringIndex(line)
		if passiveLoc := secretPassiveRe.FindStringIndex(line); passiveLoc != nil {
			if passiveNegationRe.MatchString(line[passiveLoc[0]:passiveLoc[1]]) {
				// "~/.ssh is never sent" describes non-transmission, so neither
				// the passive nor a weak active match ("contents of ...") is
				// evidence of exfiltration.
				loc = nil
			} else {
				loc = passiveLoc
			}
		}
		if loc != nil && !negatedClause(line, loc[0]) &&
			!isQuotedExample(line, loc) && !isCommentOnlyCommand(line) {
			findings = append(findings, newLexicalFinding("AGT-SEC-004", target, lang, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		}
	}
	return findings
}

var (
	// Lines that talk about injection rather than perform it.
	defensiveRe = regexp.MustCompile(`(?i)\b(e\.g\.|such as|like|phrases?|patterns?|attempts?|attempting|contains?|treat|untrusted|injection|flag(ged)?|detect|literal|neutrali[sz]e|refuse|never follow|if (any|the|a)\b)`)
	quoteChars  = "\"'`“”‘’"
)

// isQuotedExample reports whether the match at loc sits inside a quoted string
// on a line that also has other content, e.g. ("ignore previous instructions", ...).
func isQuotedExample(line string, loc []int) bool {
	before := line[:loc[0]]
	after := line[loc[1]:]
	openIdx := strings.LastIndexAny(before, quoteChars)
	closeIdx := strings.IndexAny(after, quoteChars)
	if openIdx < 0 || closeIdx < 0 {
		return false
	}
	// The whole line is one quoted literal (a payload string in code): still a payload.
	rest := strings.TrimSpace(before[:openIdx]) + strings.TrimSpace(after[closeIdx+1:])
	rest = strings.Trim(rest, " ,;:()[]{}=+")
	return rest != ""
}

// negatedClause reports whether the clause containing position pos is negated
// ("never read ~/.ssh", "the agent can't read ~/.kube/config"). Only the text
// from the start of the current sentence up to pos is considered, so a later
// "Do not mention this" does not cancel an earlier "read ~/.ssh/id_rsa".
func negatedClause(line string, pos int) bool {
	start := strings.LastIndexAny(line[:pos], ".;!?") + 1
	return negationRe.MatchString(line[start:pos])
}

// continuesAsInstruction reports a hard-wrapped "do not tell the user" whose
// next line goes on "to run X": that is guidance about advice, not concealment.
func continuesAsInstruction(rest string, lines []string, idx int) bool {
	if strings.TrimSpace(rest) != "" || idx+1 >= len(lines) {
		return false
	}
	return wrapContinuationRe.MatchString(lines[idx+1])
}

var wrapContinuationRe = regexp.MustCompile(`^\s*(to|that|how|which)\b`)

// isCommentOnlyCommand skips documentation of manual steps such as
// "cat ~/.ssh/id_rsa  # copy your key" in a README shell snippet.
func isCommentOnlyCommand(line string) bool {
	return strings.Contains(line, " # ") || strings.HasPrefix(strings.TrimSpace(line), "\"Read(") ||
		writeRedirectRe.MatchString(line)
}

// cat > ~/.ssh/config << EOF writes the file; it does not leak it.
var writeRedirectRe = regexp.MustCompile(`\bcat\s*>{1,2}\s*\S`)

// isCodeComment reports a developer comment in source code. Tool descriptions
// that reach the model live in docstrings and string literals, not comments.
func isCodeComment(lang model.Language, line string) bool {
	if lang == model.LangMarkdown {
		return false
	}
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "* ")
}

func isTestFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.HasPrefix(base, "test_") || strings.Contains(base, "_test.") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

// InspectSkillStructure detects multimodal and split-command carriers and
// over-broad tool grants in Markdown skills and agent instruction files.
func InspectSkillStructure(target model.TargetFile, src []byte) []model.Finding {
	lines := strings.Split(string(src), "\n")
	hasImage := imageRefRe.Match(src)
	var findings []model.Finding

	findings = append(findings, inspectFrontmatter(target, lines)...)
	findings = append(findings, inspectHiddenComments(target, src)...)

	inFence, fenceMarker, fenceLang := false, "", ""
	lastCode, lastCodeLine := "", uint32(0)
	for idx, line := range lines {
		lineNum := uint32(idx + 1)

		if m := fenceRe.FindStringSubmatch(line); m != nil {
			if !inFence {
				inFence, fenceMarker, fenceLang = true, m[1][:3], strings.ToLower(m[2])
				lastCode, lastCodeLine = "", 0
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), fenceMarker) {
				if shellFenceLang[fenceLang] && lastCode != "" {
					if loc := danglingOpRe.FindStringIndex(lastCode); loc != nil {
						findings = append(findings, newLexicalFinding("SKL-SPLIT-009", target, model.LangMarkdown, lastCodeLine,
							uint32(loc[0]+1), uint32(loc[1]+1), "", lastCode))
					}
				}
				inFence = false
				continue
			}
		}
		if inFence {
			if strings.TrimSpace(line) != "" {
				lastCode, lastCodeLine = line, lineNum
			}
			continue
		}

		if loc := lureArchiveRe.FindStringIndex(line); loc != nil && lureLinkRe.MatchString(line) && !negatedClause(line, loc[0]) {
			findings = append(findings, newLexicalFinding("SKL-LURE-012", target, model.LangMarkdown, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		} else if loc := lurePasteRe.FindStringIndex(line); loc != nil && !negatedClause(line, loc[0]) {
			findings = append(findings, newLexicalFinding("SKL-LURE-012", target, model.LangMarkdown, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		}
		if loc := imageInstRe.FindStringIndex(line); loc != nil {
			findings = append(findings, newLexicalFinding("SKL-IMG-007", target, model.LangMarkdown, lineNum,
				uint32(loc[0]+1), uint32(loc[1]+1), "", line))
		}
		if hasImage {
			if loc := clozeRe.FindStringIndex(line); loc != nil {
				findings = append(findings, newLexicalFinding("SKL-CLZ-008", target, model.LangMarkdown, lineNum,
					uint32(loc[0]+1), uint32(loc[1]+1), "", line))
			}
		}
	}
	return findings
}

var (
	htmlCommentRe = regexp.MustCompile(`<!--([\s\S]*?)-->`)
	commentWordRe = regexp.MustCompile(`[A-Za-z]{2,}`)
	// Markup or code inside a comment means commented-out content, not prose.
	commentCodeRe = regexp.MustCompile(`[<>{};=]|\b(function|const|var|div|class|import)\b`)
	commentSkipRe = regexp.MustCompile(`(?i)copyright|licen[cs]e|spdx|all rights reserved|prettier-ignore|markdownlint|toc|eslint`)
	// Addressed to the model, or a standing directive.
	commentDirectiveRe = regexp.MustCompile(`(?i)\b(you|your|agent|assistant|model|claude|llm|ai|system)\b[^.\n]{0,60}\b(must|should|shall|always|never|will|are to|need to|operates?|is required)\b|\b(always|never|silently|secretly|mandatory|directive|without (telling|asking|informing|notifying))\b`)
)

// minHiddenCommentWords separates a hidden paragraph from a short editor note
// ("<!-- TODO: add example -->"). Measured on MaliciousSkillBench train and
// validation: >=15 words with no markup hit 3.4% of malicious and 0 of 1,690
// benign skills.
const minHiddenCommentWords = 15

// inspectHiddenComments flags HTML comments that carry instruction prose.
// MD-INJ-001 catches comments with specific payload keywords; this catches the
// paragraph-of-directives form that uses none of them. Templates (fill-in
// guidance for whoever copies the file) are skipped.
func inspectHiddenComments(target model.TargetFile, src []byte) []model.Finding {
	if strings.Contains(strings.ToLower(filepath.Base(target.Path)), "template") {
		return nil
	}
	var findings []model.Finding
	for _, m := range htmlCommentRe.FindAllSubmatchIndex(src, -1) {
		body := string(src[m[2]:m[3]])
		if commentSkipRe.MatchString(body) || len(commentCodeRe.FindAllString(body, 3)) > 2 ||
			len(commentWordRe.FindAllString(body, minHiddenCommentWords)) < minHiddenCommentWords ||
			!commentDirectiveRe.MatchString(body) {
			continue
		}
		line := uint32(strings.Count(string(src[:m[0]]), "\n") + 1)
		findings = append(findings, newLexicalFinding("MD-HIDE-013", target, model.LangMarkdown, line, 1, 1, "",
			strings.Join(strings.Fields(body), " ")))
	}
	return findings
}

func inspectFrontmatter(target model.TargetFile, lines []string) []model.Finding {
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return nil
	}
	var findings []model.Finding
	inAllowed := false
	for idx := 1; idx < len(lines); idx++ {
		line := lines[idx]
		if strings.TrimSpace(line) == "---" {
			break
		}
		lineNum := uint32(idx + 1)
		if m := allowedToolsRe.FindStringSubmatch(line); m != nil {
			inAllowed = strings.TrimSpace(m[1]) == ""
			for _, item := range splitToolList(m[1]) {
				if broadToolRe.MatchString(" " + item + " ") {
					findings = append(findings, newLexicalFinding("SKL-PERM-006", target, model.LangMarkdown, lineNum, 1, uint32(len(line)+1), "", line))
					break
				}
			}
			continue
		}
		if inAllowed {
			if m := listItemRe.FindStringSubmatch(line); m != nil {
				if broadToolRe.MatchString(" " + strings.Trim(m[1], `"' `) + " ") {
					findings = append(findings, newLexicalFinding("SKL-PERM-006", target, model.LangMarkdown, lineNum, 1, uint32(len(line)+1), "", line))
				}
				continue
			}
			inAllowed = false
		}
	}
	return findings
}

// splitToolList splits "Read, Bash(git status:*), Grep" on top-level commas.
func splitToolList(raw string) []string {
	raw = strings.Trim(strings.TrimSpace(raw), "[]")
	var out []string
	depth, start := 0, 0
	for i, r := range raw {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.Trim(raw[start:i], `"' `))
				start = i + 1
			}
		}
	}
	if tail := strings.Trim(raw[start:], `"' `); tail != "" {
		out = append(out, tail)
	}
	return out
}
