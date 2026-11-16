;; Rule: PS-EXEC-001 (CRITICAL)
;; Detects PowerShell dynamic execution sinks receiving encoded, compressed, or
;; downloaded payloads via direct nesting or 1-hop variable taint.

;; Pattern A: execution sink whose command text contains a decode/download call
(command
  (command_name) @sink_cmd
) @finding
(#match? @sink_cmd "(?i)^(iex|invoke-expression|invoke-command|powershell|pwsh|start-process)$")
(#match? @finding "(?i)(frombase64string|frombase64transform|encodedcommand|-enc\\b|gzipstream|deflatestream|invoke-webrequest|downloadstring|downloaddata)")

;; Pattern B: 1-hop variable taint into IEX / Invoke-Expression
(
  (pipeline
    (assignment_expression
      (left_assignment_expression) @tainted_var
      value: (pipeline) @taint_rhs))
  (_)*
  (pipeline
    (pipeline_chain
      (command
        (command_name) @sink_cmd
        (command_elements
          (command_argument_sep)
          (array_literal_expression
            (unary_expression
              (variable) @sink_var)))))) @finding
  (#eq? @tainted_var @sink_var)
  (#match? @sink_cmd "(?i)^(iex|invoke-expression)$")
  (#match? @taint_rhs "(?i)(frombase64string|frombase64transform|gzipstream|deflatestream|invoke-webrequest|downloadstring|downloaddata)")
)

;; Pattern C: Add-Type compiling inline source that was decoded or downloaded
(command
  name: (command_name) @sink_cmd
) @finding
(#match? @sink_cmd "(?i)^add-type$")
(#match? @finding "(?i)-typedefinition")
(#match? @finding "(?i)(frombase64string|downloadstring|downloaddata|invoke-webrequest|readallbytes)")

;; Pattern D: reflection assembly loading of decoded or downloaded bytes
(invokation_expression) @finding
(#match? @finding "(?i)\\[[^]]*assembly\\]::(load|loadfrom)\\b")
(#match? @finding "(?i)(frombase64string|downloadstring|downloaddata|invoke-webrequest|readallbytes)")

;; Pattern E: download to a file, then invoke the downloaded file
(statement_list
  (pipeline
    (pipeline_chain
      (command
        (command_name) @fetch_cmd)) @fetch_stmt)
  (_)*
  (pipeline
    (pipeline_chain
      (command
        (command_invokation_operator)
        (command_name_expr) @exec_cmd)) @exec_stmt) @finding
  (#match? @fetch_cmd "(?i)^(invoke-webrequest|invoke-restmethod|start-bitstransfer|curl|wget)$")
  (#match? @fetch_stmt "(?i)-outfile")
)
