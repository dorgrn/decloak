;; Rule: SH-EXEC-001 (CRITICAL)
;; Detects base64/openssl/xxd/uudecode decoding piped or substituted into a
;; shell execution sink (eval, bash -c, sh -c, zsh, dash, ksh).

;; Pattern A: decoder output substituted into eval/bash -c/sh -c
(command
  name: (command_name (word) @sink_cmd)
  argument: [
    (string (command_substitution) @payload)
    (command_substitution) @payload
  ]
) @finding
(#match? @sink_cmd "^(eval|bash|sh|zsh|dash|ksh)$")
(#match? @payload "(?i)(base64[[:space:]]+(-d|--decode)|openssl[[:space:]]+enc[[:space:]]+-d|xxd[[:space:]]+-r|uudecode)")

;; Pattern B (variable taint: x=$(... | base64 -d); eval "$x") is implemented
;; in Go (shellTaint in shell_taint.go). As a query it needed a `(_)*` wildcard
;; that took seconds on scripts with many assignments.

;; Pattern C: decoder command piped into a shell/interpreter
(pipeline
  (command
    name: (command_name (word) @decode_cmd)) @decoder
  (command
    name: (command_name (word) @sink_cmd)) @sink
) @finding
(#match? @decode_cmd "^(base64|openssl|xxd|uudecode)$")
(#match? @sink_cmd "^(bash|sh|zsh|dash|ksh|eval|python|perl|ruby|node)$")

;; Pattern D: decoder output used as a process substitution for `source` / `.`
(command
  name: (command_name (word) @sink_cmd)
  argument: (process_substitution
    [
      (command
        name: (command_name (word) @decode_cmd))
      (pipeline
        (command
          name: (command_name (word) @decode_cmd)))
    ])
) @finding
(#match? @sink_cmd "^(source|\\.)$")
(#match? @decode_cmd "^(base64|openssl|xxd|uudecode)$")

;; Pattern E: decoder output piped through intermediate commands into a shell
(pipeline
  (command
    name: (command_name (word) @decode_cmd))
  (_)*
  (command
    name: (command_name (word) @sink_cmd)) @sink
) @finding
(#match? @decode_cmd "^(base64|openssl|xxd|uudecode)$")
(#match? @sink_cmd "^(bash|sh|zsh|dash|ksh|eval|python|perl|ruby|node)$")
