;; Rule: SH-DL-001 (CRITICAL)
;; Detects remote downloads (curl/wget/fetch) substituted or piped directly into
;; a shell/interpreter for execution.

;; Pattern A: download command substitution inside eval/bash -c/sh -c
(command
  name: (command_name (word) @sink_cmd)
  argument: [
    (string (command_substitution) @payload)
    (command_substitution) @payload
  ]
) @finding
(#match? @sink_cmd "^(eval|bash|sh|zsh|dash|ksh)$")
(#match? @payload "(?i)(curl[[:space:]]|wget[[:space:]]|fetch[[:space:]])")

;; Pattern B: download command piped into a shell/interpreter
(pipeline
  (command
    name: (command_name (word) @fetch_cmd)) @fetcher
  (command
    name: (command_name (word) @sink_cmd)) @sink
) @finding
(#match? @fetch_cmd "^(curl|wget|fetch)$")
(#match? @sink_cmd "^(bash|sh|zsh|dash|ksh|eval|python|perl|ruby|node)$")

;; Pattern C: download used as a process substitution for `source` / `.`
(command
  name: (command_name (word) @sink_cmd)
  argument: (process_substitution
    [
      (command
        name: (command_name (word) @fetch_cmd))
      (pipeline
        (command
          name: (command_name (word) @fetch_cmd)))
    ])
) @finding
(#match? @sink_cmd "^(source|\\.)$")
(#match? @fetch_cmd "^(curl|wget|fetch)$")

;; Pattern D: download piped through intermediate commands into a shell
(pipeline
  (command
    name: (command_name (word) @fetch_cmd))
  (_)*
  (command
    name: (command_name (word) @sink_cmd)) @sink
) @finding
(#match? @fetch_cmd "^(curl|wget|fetch)$")
(#match? @sink_cmd "^(bash|sh|zsh|dash|ksh|eval|python|perl|ruby|node)$")
