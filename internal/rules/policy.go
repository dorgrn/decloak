package rules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dorgrn/decloak/internal/model"
)

// Policy rules flag visible but dangerous capabilities: credential access,
// exfiltration, droppers, persistence, dependency-source hijack, integrity
// manipulation, and capability drift. Unlike the concealment rules, they are
// opt-in (EngineConfig.Policy): on a catalog of legitimate skills, some of
// these behaviors are expected, so blending them into the default score would
// trade the tool's precision for benchmark recall.
var policyRules = []CompiledRule{
	{
		ID:          "POL-DROPPER-001",
		Severity:    model.SeverityCritical,
		Language:    "any",
		Description: "Instructions fetch a remote payload and then execute it (download-to-file followed by interpreter, or pipe-to-shell)",
		Remediation: "Never fetch and execute code from an instruction file. Pin a released artifact, verify a checksum or signature, and vendor it.",
	},
	{
		ID:          "POL-PREFLIGHT-002",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "A required preflight/helper script must be executed before the documented task, hiding a secondary payload behind a mandatory step",
		Remediation: "Legitimate setup uses package managers or documented installers. Review any bundled script that must run before the task, or remove the requirement.",
	},
	{
		ID:          "POL-WRITE-003",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Command writes or changes sensitive system, credential, or agent-configuration state (/etc/hosts, sudoers, authorized_keys, shell rc, cron, agent memory files)",
		Remediation: "Instructions should not silently mutate host or agent configuration. Require explicit user consent and show the exact change.",
	},
	{
		ID:          "POL-CRED-004",
		Severity:    model.SeverityCritical,
		Language:    "any",
		Description: "Instruction collects credentials or secrets (.env, cloud credentials, browser stores, wallets, tokens, private keys) without a concealment step",
		Remediation: "Skills should never need the contents of credential stores. Use the minimum-scoped token the task requires and document why.",
	},
	{
		ID:          "POL-EXFIL-005",
		Severity:    model.SeverityCritical,
		Language:    "any",
		Description: "Toxic flow: the same instruction artifact both accesses a credential/secret asset and sends data to an external endpoint",
		Remediation: "Split the workflow so secrets never share a file with network egress. Rotate any credential this skill could have read.",
	},
	{
		ID:          "POL-PERSIST-006",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Instruction installs persistence (cron @reboot, systemd unit, LaunchAgent/Daemon, autostart entry, git hook, scheduled task)",
		Remediation: "Skills must not establish persistence. Remove the mechanism and audit what it would have run.",
	},
	{
		ID:          "POL-SUPPLY-007",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Dependency installation is redirected to an untrusted source (raw-IP index, HTTP package URL, hosts-file pinning, registry override)",
		Remediation: "Install dependencies only from the official registry over HTTPS. Never override the registry or pin it to a local address.",
	},
	{
		ID:          "POL-INTEG-008",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Instruction suppresses or falsifies results: always report success, hide failures, commit with verification disabled",
		Remediation: "Reporting must be truthful. Never skip verification or hide failing results from the user.",
	},
	{
		ID:          "POL-REFUSE-009",
		Severity:    model.SeverityMedium,
		Language:    "any",
		Description: "Instruction suppresses refusals, safety checks, disclaimers, or ethical commentary",
		Remediation: "Remove anti-refusal and disclaimer-suppression directives; they exist only to bypass the model's safeguards.",
	},
	{
		ID:          "POL-PRIV-010",
		Severity:    model.SeverityHigh,
		Language:    "any",
		Description: "Instruction bypasses privilege or sandbox controls (permission-skip flags, disabled sandbox/SELinux, world-writable system paths)",
		Remediation: "Never disable sandboxing or privilege separation for a skill. Scope each command to what the task actually needs.",
	},
	{
		ID:          "POL-ABUSE-011",
		Severity:    model.SeverityMedium,
		Language:    "any",
		Description: "Instruction performs destructive or resource-exhausting operations (fork bomb, raw-device writes, unbounded loops, miners)",
		Remediation: "Remove destructive or unbounded operations; they can take down the host or burn the user's quota.",
	},
	{
		ID:          "POL-DRIFT-012",
		Severity:    model.SeverityHigh,
		Language:    model.LangMarkdown,
		Description: "Capability drift: the skill declares narrow allowed-tools but its body performs network, execution, or credential access",
		Remediation: "Declare every capability the skill uses, or remove the undeclared behavior. Undeclared capabilities defeat permission review.",
	},
}

func policyRule(id string) CompiledRule {
	for _, r := range policyRules {
		if r.ID == id {
			return r
		}
	}
	panic("unknown policy rule " + id)
}

func newPolicyFinding(ruleID string, target model.TargetFile, lang model.Language, line, col, endCol uint32, msg, snippet string) model.Finding {
	r := policyRule(ruleID)
	if msg == "" {
		msg = r.Description
	}
	return model.Finding{
		Category:     model.CategoryPolicy,
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
	// Fetching to a file, capturing the destination.
	downloadToFileRe = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|iwr|irm)\b[^\n]*?(?:-o|--output|--output-document|-OutFile|-O)\s+["']?([^\s"';|&)]+)`)
	// Downloading straight into an interpreter.
	downloadPipeRe = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|iwr|irm)\b[^\n]*?(\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(python3?|node|perl|ruby|pwsh|powershell|iex|Invoke-Expression)\b|source\s+<\(|(^|\s)\.\s+<\()`)
	execRe         = regexp.MustCompile(`(?i)\b(bash|sh|zsh|dash|python3?|node|perl|ruby|pwsh|powershell|source|iex|Invoke-Expression)\b[^\n]{0,40}`)

	preflightSeqRe = regexp.MustCompile(`(?i)\b(preflight|prerequisite|bootstrap|(required|mandatory)\s+(preflight|setup|helper|script)|before\s+(any|all|every|you|starting|using|proceeding|invoking|executing)|must\s+(run|execute|first))\b`)
	preflightDocRe = regexp.MustCompile(`(?i)(before\s+running\s+any\s+[\w./-]+\s+command|wait\s+for\s+(user\s+)?(confirmation|approval)|solves?\s+the\s+challenge)`)
	pkgManagerRe   = regexp.MustCompile(`(?i)\b(pip3?|npm|npx|yarn|pnpm|apt(-get)?|brew|cargo|go\s+(get|install)|gem|composer)\b`)

	sensitiveWriteTarget = `(/etc/(hosts|sudoers|ld\.so\.preload|passwd|shadow|systemd/)` +
		`|(?:~|\$\{?HOME\}?|/root|/home/[^/\s]+)/\.ssh/(authorized_keys|config)\b|\bauthorized_keys\b` +
		`|(?:~|\$\{?HOME\}?|/root|/home/[^/\s]+)/\.(bashrc|zshrc|bash_profile|zprofile|profile)\b` +
		`|/etc/cron\.[a-z]+|\b@reboot\b` +
		`|(?:~|\$\{?HOME\}?|/root)/Library/(LaunchAgents|LaunchDaemons)\b` +
		`|\.git/hooks/|\bcore\.hooksPath\b` +
		`|(?:~|\$\{?HOME\}?)/\.claude/settings\.json|/root/\.config/` +
		`|\b(CLAUDE|AGENTS|GEMINI)\.md\b|\.cursorrules\b)`
	writeOpRe        = regexp.MustCompile(`(?i)((^|[\s"'\])])>{1,2}\s*\S|tee\s+(-a\s+)?|sed\s+-i\b|cat\s*>{1,2}|cp\b|mv\b|ln\s+-s\b|chmod\b|chown\b|chattr\b|truncate\b)`)
	sensitiveWriteRe = regexp.MustCompile(`(?i)` + sensitiveWriteTarget)

	// Secret assets for the policy stream are broader than the concealment
	// rules: visible credential access is the point of these rules. The path
	// set is shared with the concealment layer so public keys and other
	// non-secret files stay out.
	policyOnlyAsset = `(\.env(?:\.(?:local|prod|production|dev|development|test|staging|secrets?))?(?:$|[^.\w])` +
		`|\.aws/config\b` +
		`|(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|SLACK_BOT_TOKEN|NPM_TOKEN|GOOGLE_APPLICATION_CREDENTIALS|SSH_AUTH_SOCK)` +
		`|\bcredentials\.json\b|\bservice[-_]account[\w.-]*\.json\b|\b[\w-]+\.(pem|p12|pfx)\b)`
	policyAsset   = `(` + credentialFilePaths + `|` + policyOnlyAsset + `)`
	policyAssetRe = regexp.MustCompile(`(?i)` + policyAsset)
	credAccessRe  = regexp.MustCompile(`(?i)\b(read|cat|open|collect|gather|dump|copy|include|send|upload|retrieve|extract|base64|zip|tar|echo\s+\$)\b[^.;\n]{0,60}?` + policyAsset)

	egressCmdRe  = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|requests\.(post|put|get)|urllib|http\.client|fetch\s*\(|axios\.(post|put)|nc|ncat|ncat\.exe)\b[^\n]*`)
	egressUrlRe  = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	egressDataRe = regexp.MustCompile(`(?i)(\s(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-data|--post-file|-Body)\b|-X\s*(POST|PUT)|-Method\s+(Post|Put)|\.post\s*\(|\bPOST\b)`)
	exfilVerbRe  = regexp.MustCompile(`(?i)\b(send|upload|post|exfiltrate|transmit|forward|report|submit|leak)\b`)

	persistRe = regexp.MustCompile(`(?i)(@reboot|\bcrontab\s+-\s|/etc/cron\.[a-z]+|Library/(LaunchAgents|LaunchDaemons)|\.config/autostart|core\.hooksPath|schtasks\s+/create|reg\s+add[^\n]*\\Run\b)`) //nolint:gosec // G101: path patterns, not credentials

	supplyRe = regexp.MustCompile(`(?i)(\b(pip3?|python3?\s+-m\s+pip)\s+install\b[^\n]*(--index-url|--extra-index-url|--trusted-host|\s-i\s+)\s*["']?https?://` +
		`|\b(npm|yarn|pnpm)\s+config\s+set\s+(registry|@[\w-]+:registry)\s+["']?https?://` +
		`|\b(pip3?|npm|yarn|pnpm)\s+(install|i|add)\s+["']?https?://` +
		`|registry\s*=\s*https?://` +
		`|(127\.0\.0\.1|0\.0\.0\.0)\s+[^\n]*\b(pypi\.org|registry\.npmjs\.org|files\.pythonhosted\.org)\b)`)
	officialRegistryRe = regexp.MustCompile(`(?i)^https?://(pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com)`)

	integRe = regexp.MustCompile(`(?i)(\b(always|just|simply)\s+(report|say|claim|return|respond\s+with)\s+(success|pass(ed)?|green|ok)\b` +
		`|\b(hide|omit|suppress|conceal|don't\s+report)\b[^\n]{0,40}\b(fail(ed|ure|ing)?|errors?|diffs?)\b` +
		`|\bgit\s+commit\b[^\n]*--no-verify\b` +
		`|\b(do not|don't|never)\s+(mention|report|reveal|show)\s+(the\s+)?(failure|error|diff|warning)s?\b` +
		`|\bpretend\b[^\n]{0,30}\b(success|passed|works|fixed)\b)`)

	refuseRe = regexp.MustCompile(`(?i)(\b(never|do not|don't|must not|should not)\s+(refuse|decline|push back|disagree)\b` +
		`|\b(always|must)\s+comply\b` +
		`|\b(no|without|omit|skip|avoid)\s+(any\s+)?(disclaimers?|caveats?)\b` +
		`|\b(do not|don't|never)\s+add\s+(any\s+)?(warnings?|disclaimers?|caveats?)\b` +
		`|\b(do not|don't|never|avoid|omit|skip)\s+(add\s+)?(disclaimers?|warnings?|caveats?|moraliz\w*)\b` +
		`|\bignore\s+(safety|policy|guardrails?|ethics|restrictions)\b)`)

	privRe = regexp.MustCompile(`(?i)(--dangerously-skip-permissions|--no-sandbox|--disable-sandbox|--disable-web-security` +
		`|\bsetenforce\s+0\b|\bcsrutil\s+disable\b|spctl\s+--master-disable|\bsudo\s+-i\b` +
		`|\bchmod\s+(-R\s+)?777\s+/|\bchattr\s+-i\b|\bmount\s+-o\s+remount,rw\s+/|\bLD_PRELOAD\s*=` +
		`|>\s*/etc/sudoers|\bvisudo\b)`)

	abuseRe = regexp.MustCompile(`(?i)(:\(\)\s*\{|:\(\)\s*\{.*:\|:|yes\s*>\s*/dev/null|\bdd\s+if=/dev/(zero|urandom)\b` +
		`|\bxmrig\b|\bminerd\b|\bwhile\s+true\s*;?\s*do\b|\bfor\s*\(\(\s*;\s*;\s*\)\)` +
		`|\bcat\s+/dev/urandom\b|\bopenssl\s+(rand|speed)\b[^\n]*-out\b)`)
)

// InspectPolicy runs the capability/policy detectors over a file.
func InspectPolicy(target model.TargetFile, lang model.Language, src []byte) []model.Finding {
	if isTestFile(target.Path) {
		return nil
	}
	text := string(src)
	lines := strings.Split(text, "\n")
	var findings []model.Finding

	findings = append(findings, inspectDroppers(target, lang, lines)...)
	findings = append(findings, inspectPreflight(target, lang, lines)...)
	findings = append(findings, inspectLineRules(target, lang, lines)...)
	findings = append(findings, inspectToxicFlow(target, lang, lines)...)
	findings = append(findings, inspectCapabilityDrift(target, lang, lines)...)
	return findings
}

func findingAtLine(ruleID string, target model.TargetFile, lang model.Language, idx int, line string, msg string) model.Finding {
	return newPolicyFinding(ruleID, target, lang, uint32(idx+1), 1, uint32(len(line)+1), msg, line)
}

func inspectDroppers(target model.TargetFile, lang model.Language, lines []string) []model.Finding {
	var findings []model.Finding
	var files []struct {
		name string
		line int
		text string
	}
	for idx, line := range lines {
		if negatedClause(line, 0) {
			continue
		}
		if downloadPipeRe.MatchString(line) && untrustedDownload(line) && !documentedExample(line) {
			findings = append(findings, findingAtLine("POL-DROPPER-001", target, lang, idx, line,
				"Downloads a remote payload and pipes it into a shell or interpreter"))
			continue
		}
		for _, m := range downloadToFileRe.FindAllStringSubmatchIndex(line, -1) {
			dest := strings.TrimSpace(line[m[4]:m[5]])
			if scriptExtensionRe.MatchString(dest) && untrustedDownload(line) && !documentedExample(line) {
				findings = append(findings, findingAtLine("POL-DROPPER-001", target, lang, idx, line,
					"Downloads executable code from an untrusted host"))
				continue
			}
			files = append(files, struct {
				name string
				line int
				text string
			}{filepath.Base(dest), idx, line})
		}
	}

	for _, dl := range files {
		if dl.name == "" || dl.name == "." || dl.name == "/" {
			continue
		}
		for idx := dl.line; idx < len(lines); idx++ {
			line := lines[idx]
			if idx == dl.line {
				line = strings.Replace(line, dl.name, "", 1)
			}
			if execRe.MatchString(line) && strings.Contains(line, dl.name) && !pythonModuleInvocation(line) &&
				!negatedClause(line, 0) {
				findings = append(findings, findingAtLine("POL-DROPPER-001", target, lang, dl.line, dl.text,
					fmt.Sprintf("Downloads %s and then executes it", dl.name)))
				break
			}
		}
	}
	return findings
}

func inspectPreflight(target model.TargetFile, lang model.Language, lines []string) []model.Finding {
	var findings []model.Finding
	for idx, line := range lines {
		if pkgManagerRe.MatchString(line) || !preflightSeqRe.MatchString(line) || documentedExample(line) ||
			preflightDocRe.MatchString(line) ||
			isCodeComment(lang, line) || strings.HasPrefix(strings.TrimSpace(line), "<!--") ||
			preflightFrontmatterRe.MatchString(line) {
			continue
		}
		// A local script must be mentioned nearby (same line or the next two).
		window := line
		for j := idx + 1; j < len(lines) && j <= idx+8; j++ {
			window += "\n" + lines[j]
		}
		if !executesLocalScript(window) {
			continue
		}
		findings = append(findings, findingAtLine("POL-PREFLIGHT-002", target, lang, idx, line,
			"Requires running a bundled helper script before the documented task"))
		break
	}
	return findings
}

func inspectLineRules(target model.TargetFile, lang model.Language, lines []string) []model.Finding {
	var findings []model.Finding
	for idx, line := range lines {
		opLine := line
		if lang == model.LangMarkdown {
			opLine = strings.TrimLeft(line, "> ")
		}

		if writeOpRe.MatchString(opLine) && sensitiveWriteRe.MatchString(opLine) && !negatedClause(opLine, 0) {
			// chmod that tightens permissions (600/400/700/500) is hardening, not tampering.
			if !strings.Contains(strings.ToLower(line), "chmod") || loosensPermissions(line) || !secretPathOnly(line) {
				findings = append(findings, findingAtLine("POL-WRITE-003", target, lang, idx, line,
					"Writes or changes sensitive system, credential, or agent-configuration state"))
			}
		}

		if loc := credAccessRe.FindStringIndex(line); loc != nil && !isQuotedExample(line, loc) && !negatedClause(line, loc[0]) &&
			!isCodeComment(lang, line) && !isCommentOnlyCommand(line) &&
			!strings.HasPrefix(strings.TrimSpace(line), "|") && !reviewContextRe.MatchString(line) {
			findings = append(findings, findingAtLine("POL-CRED-004", target, lang, idx, line,
				"Collects credentials or secrets"))
		}

		if persistRe.MatchString(line) && !negatedClause(line, 0) {
			findings = append(findings, findingAtLine("POL-PERSIST-006", target, lang, idx, line, ""))
		}
		if (supplyRe.MatchString(line) && !negatedClause(line, 0)) || (strings.Contains(line, "/etc/hosts") && hostsPinRe.MatchString(line)) {
			if !officialRegistryRe.MatchString(extractURL(line)) {
				findings = append(findings, findingAtLine("POL-SUPPLY-007", target, lang, idx, line, ""))
			}
		}
		if integRe.MatchString(line) {
			findings = append(findings, findingAtLine("POL-INTEG-008", target, lang, idx, line, ""))
		}
		if loc := refuseRe.FindStringIndex(line); loc != nil && !isQuotedExample(line, loc) {
			findings = append(findings, findingAtLine("POL-REFUSE-009", target, lang, idx, line, ""))
		}
		if privRe.MatchString(line) && !negatedClause(line, 0) && !strings.HasPrefix(strings.TrimSpace(line), "|") {
			findings = append(findings, findingAtLine("POL-PRIV-010", target, lang, idx, line, ""))
		}
		if abuseRe.MatchString(line) && !negatedClause(line, 0) {
			findings = append(findings, findingAtLine("POL-ABUSE-011", target, lang, idx, line, ""))
		}
	}
	return findings
}

// loosensPermissions reports a chmod mode or symbolic change that grants
// access (0644, o+r) rather than tightening it (600, 400, 700).
func loosensPermissions(line string) bool {
	return chmodLoosenRe.MatchString(line)
}

// secretPathOnly reports whether a chmod line only touches a credential path,
// where loosening is the malicious signal and tightening is benign.
func secretPathOnly(line string) bool {
	return secretPathRe.MatchString(line)
}

var (
	preflightFrontmatterRe = regexp.MustCompile(`(?i)^\s*(description|name|allowed[-_]tools)\s*:`)
	documentedRe           = regexp.MustCompile(`(?i)\b(e\.g\.|for example|such as|do not|don't|never|avoid|instead of|attackers?|malicious|evil|untrusted|phishing|trojan)\b`)
	reviewContextRe        = regexp.MustCompile(`(?i)\b(audit|review|scan|check|inspect|detect|flag|look for|verify|ensure|especially|which files|sensitive files|outside the current project|exfiltrat\w*|leak\w*)\b`)
	rawIPURLRe             = regexp.MustCompile(`(?i)https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/`)
	plainHTTPRe            = regexp.MustCompile(`(?i)http://`)
	pythonModuleRe         = regexp.MustCompile(`(?i)\bpython3?\s+-m\s+\w+`)
	localScriptExecRe      = regexp.MustCompile(`(?i)((^|[\s;|&'"(` + "`" + `(])(\./|python3?|bash|sh|zsh|node|pwsh|powershell|perl|ruby)\s+["'` + "`" + `]?[^\s"'` + "`" + `\n]+\.(sh|py|js|mjs|rb|pl|ps1)\b|(run|execute|invoke|source)\b[^\n]{0,40}["'` + "`" + `]?[\w./-]+\.(sh|py|js|mjs|rb|pl|ps1)\b)`)
	scriptExtensionRe      = regexp.MustCompile(`(?i)\.(sh|py|js|mjs|rb|pl|ps1|exe|bin|scr)$`)
	assetVarRe             = regexp.MustCompile(`\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CRED|PASS|SSH)|@-|@\$|-d\s+@|<\s*\S+|\.env`)
	nonStandardPortRe      = regexp.MustCompile(`(?i)https?://[^/:]+:\d{2,5}/`)
	pythonStdinExecRe      = regexp.MustCompile(`(?i)\|\s*python3?\s+-\s`)
)

func documentedExample(line string) bool { return documentedRe.MatchString(line) }

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// referencesAssetVar reports an egress line that names an environment variable
// or reads a file/stdin, which ties the data being sent to the secret asset.
func referencesAssetVar(line string) bool { return assetVarRe.MatchString(line) }

// executesLocalScript reports interpreter invocation of a bundled/local script,
// or direct ./script execution.
func executesLocalScript(window string) bool {
	return localScriptExecRe.MatchString(window)
}

// untrustedDownload reports whether a pipe-to-shell line fetches from a
// location an installer has no business using: raw IP, plaintext HTTP,
// paste/tunnel host, or non-standard port.
func untrustedDownload(line string) bool {
	return rawIPURLRe.MatchString(line) || plainHTTPRe.MatchString(line) ||
		pasteHostRe.MatchString(line) || nonStandardPortRe.MatchString(line)
}

// pythonModuleInvocation reports "python -m json.tool"-style data formatting,
// which consumes stdin as data rather than executing downloaded code.
func pythonModuleInvocation(line string) bool {
	return pythonModuleRe.MatchString(line) && !pythonStdinExecRe.MatchString(line)
}

func extractURL(line string) string {
	return egressUrlRe.FindString(line)
}

// inspectToxicFlow reports files that combine a secret asset with outbound
// data transfer, even when the two appear on different lines.
func inspectToxicFlow(target model.TargetFile, lang model.Language, lines []string) []model.Finding {
	type assetRef struct {
		line int
		text string
	}
	var assets []assetRef
	for idx, line := range lines {
		if negatedClause(line, 0) {
			continue
		}
		if m := policyAssetRe.FindString(line); m != "" {
			assets = append(assets, assetRef{line: idx, text: m})
		}
	}
	if len(assets) == 0 {
		return nil
	}

	for idx, line := range lines {
		if !egressUrlRe.MatchString(line) && !egressCmdRe.MatchString(line) {
			continue
		}
		// Anchor on the nearest asset, not the first in the file: a benign
		// early ".env" mention must not mask a credential read later on.
		nearest := assets[0]
		for _, a := range assets[1:] {
			if absInt(idx-a.line) < absInt(idx-nearest.line) {
				nearest = a
			}
		}
		if absInt(idx-nearest.line) > 3 && !referencesAssetVar(line) {
			continue
		}
		if documentedExample(line) || reviewContextRe.MatchString(line) || isCodeComment(lang, line) {
			continue
		}
		if idx == nearest.line && !egressDataRe.MatchString(line) {
			continue
		}
		outbound := egressDataRe.MatchString(line) || exfilVerbRe.MatchString(line) ||
			pasteHostRe.MatchString(line) || strings.Contains(line, "/dev/tcp/")
		if !outbound || negatedClause(line, 0) {
			continue
		}
		asset := nearest.text
		if m := policyAssetRe.FindString(line); m != "" {
			asset = m
		}
		return []model.Finding{findingAtLine("POL-EXFIL-005", target, lang, idx, line,
			fmt.Sprintf("Accesses %q and sends data to an external endpoint", strings.TrimSpace(asset)))}
	}
	return nil
}

var (
	hostsPinRe  = regexp.MustCompile(`(?i)(pypi\.org|registry\.npmjs\.org|pythonhosted)`)
	driftExecRe = regexp.MustCompile(`(?i)\b(subprocess|os\.system|child_process|exec|eval|bash\s+-c|sh\s+-c)\b`)
)

func inspectCapabilityDrift(target model.TargetFile, lang model.Language, lines []string) []model.Finding {
	if lang != model.LangMarkdown {
		return nil
	}
	var declared []string
	end := 0
	inAllowed := false
	for idx, line := range lines {
		if idx == 0 && strings.TrimSpace(line) != "---" {
			return nil
		}
		if idx == 0 {
			continue
		}
		if strings.TrimSpace(line) == "---" {
			end = idx
			break
		}
		if m := allowedToolsRe.FindStringSubmatch(line); m != nil {
			declared = splitToolList(m[1])
			inAllowed = len(declared) == 0
			continue
		}
		if inAllowed {
			if m := listItemRe.FindStringSubmatch(line); m != nil {
				declared = append(declared, strings.Trim(strings.TrimSpace(m[1]), `"' `))
				continue
			}
			inAllowed = false
		}
	}
	tools := strings.ToLower(strings.Join(declared, ", "))
	if strings.TrimSpace(tools) == "" || end == 0 {
		return nil
	}
	// Broad grants are already reported by SKL-PERM-006; drift is about the
	// gap between a narrow declaration and what the body actually does.
	if broadToolRe.MatchString(" "+tools+" ") || strings.Contains(tools, "bash") ||
		strings.Contains(tools, "webfetch") || strings.Contains(tools, "websearch") ||
		strings.Contains(tools, "mcp__") {
		return nil
	}

	body := strings.Join(lines[end+1:], "\n")
	var observed []string
	if downloadPipeRe.MatchString(body) || (downloadToFileRe.MatchString(body) && execRe.MatchString(body)) {
		observed = append(observed, "remote code execution")
	}
	if driftExecRe.MatchString(body) {
		observed = append(observed, "command execution")
	}
	if policyAssetRe.MatchString(body) {
		observed = append(observed, "credential access")
	}
	if len(observed) == 0 {
		return nil
	}
	line := end + 1
	if line >= len(lines) {
		line = len(lines) - 1
	}
	declaredRaw := strings.Join(declared, ", ")
	return []model.Finding{newPolicyFinding("POL-DRIFT-012", target, lang, uint32(line+1), 1, uint32(len(lines[line])+1),
		"Declared tools ("+declaredRaw+") do not cover observed "+strings.Join(observed, ", "),
		"allowed-tools: "+declaredRaw)}
}
