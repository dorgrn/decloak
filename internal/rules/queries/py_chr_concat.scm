;; Rule: PY-OBF-002 (HIGH)
;; Detects dynamic character concatenation chains (e.g., chr(101) + chr(118) + ... or "".join([chr(...) ...]))
;; feeding directly or via 1-hop variable taint into Python execution sinks or getattr().

;; Pattern A: chr() concatenation chain passed directly into an execution sink or getattr()
(call
  function: (identifier) @sink_fn
  (#match? @sink_fn "^(eval|exec|compile|getattr|__import__)$")
  arguments: (argument_list
    (binary_operator) @chain
  )
) @finding
(#match? @chain "(?s)chr\\([^)]*\\)\\s*\\+\\s*.*chr\\(")

;; Pattern B: 1-hop variable taint from a chr() concatenation chain into an execution sink
;; Matches sibling statements because this grammar has no `expression_statement`
;; wrapper, and captures `@finding` on the sink call (not the grouping root).
(
  (assignment
    left: (identifier) @tainted_var
    right: (binary_operator) @taint_rhs
  )
  (_)*
  (call
    function: [
      (identifier) @sink_fn
      (attribute attribute: (identifier) @sink_fn)
    ]
    (#match? @sink_fn "^(eval|exec|compile|getattr|__import__|system|popen|run|Popen|call|check_output)$")
    arguments: (argument_list
      (identifier) @sink_arg
    )
  ) @finding
  (#eq? @tainted_var @sink_arg)
  (#match? @taint_rhs "(?s)chr\\([^)]*\\)\\s*\\+\\s*.*chr\\(")
)
