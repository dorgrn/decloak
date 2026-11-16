;; Rule: JS-EXEC-001 / TS-EXEC-001 (CRITICAL)
;; Detects JavaScript/TypeScript execution sinks (eval, Function, child_process.exec/execSync/spawn)
;; paired with decoding calls (atob, decodeURIComponent, Buffer.from) or String.fromCharCode
;; via direct nesting (Pattern A) or 1-hop variable taint (Pattern B).

;; decodeURIComponent and bare `from` (Array.from) are not obfuscation decoders.
;; Buffer.from(x, "base64") is covered by the Go taint pass.

;; Pattern A: Direct nesting inside eval() or Function()
;; A regex literal receiver (/re/.exec(...)) is RegExp.prototype.exec, not a sink.
(call_expression
  function: [
    (identifier) @sink_fn
    (member_expression object: [(identifier) (member_expression) (call_expression)] property: (property_identifier) @sink_fn)
  ]
  (#match? @sink_fn "^(eval|Function|exec|execSync|execFile|execFileSync|fork|spawn|spawnSync|runInThisContext|runInNewContext|runInContext|compileFunction)$")
  arguments: (arguments
    (call_expression
      function: [
        (identifier) @decode_fn
        (member_expression property: (property_identifier) @decode_fn)
      ]
      (#match? @decode_fn "^(atob|unescape|fromCharCode|fromBase64|decompress|inflateSync|gunzipSync)$")
    )
  )
) @finding

;; Pattern C: new Function(decoded_payload)
(new_expression
  constructor: (identifier) @sink_fn
  (#eq? @sink_fn "Function")
  arguments: (arguments
    (call_expression
      function: [
        (identifier) @decode_fn
        (member_expression property: (property_identifier) @decode_fn)
      ]
      (#match? @decode_fn "^(atob|unescape|fromCharCode|fromBase64|decompress|inflateSync|gunzipSync)$")
    )
  )
) @finding

;; Pattern B: 1-hop variable taint (const payload = atob(...); eval(payload))
;; `@finding` is attached to the sink call because gotreesitter does not emit
;; captures on the synthetic grouping root of multi-statement patterns.
(
  (lexical_declaration
    (variable_declarator
      name: (identifier) @tainted_var
      value: (call_expression
        function: [
          (identifier) @decode_fn
          (member_expression property: (property_identifier) @decode_fn)
        ]
        (#match? @decode_fn "^(atob|unescape|fromCharCode|fromBase64|decompress|inflateSync|gunzipSync)$")
      )
    )
  )
  (_)*
  (expression_statement
    (call_expression
      function: [
        (identifier) @sink_fn
        (member_expression property: (property_identifier) @sink_fn)
      ]
      (#match? @sink_fn "^(eval|Function|exec|execSync|execFile|execFileSync|fork|spawn|spawnSync|runInThisContext|runInNewContext|runInContext|compileFunction)$")
      arguments: (arguments
        (identifier) @sink_arg
      )
    ) @finding
  )
  (#eq? @tainted_var @sink_arg)
)

;; Pattern B2: 1-hop variable taint using `var` declarations
(
  (variable_declaration
    (variable_declarator
      name: (identifier) @tainted_var
      value: (call_expression
        function: [
          (identifier) @decode_fn
          (member_expression property: (property_identifier) @decode_fn)
        ]
        (#match? @decode_fn "^(atob|unescape|fromCharCode|fromBase64|decompress|inflateSync|gunzipSync)$")
      )
    )
  )
  (_)*
  (expression_statement
    (call_expression
      function: [
        (identifier) @sink_fn
        (member_expression property: (property_identifier) @sink_fn)
      ]
      (#match? @sink_fn "^(eval|Function|exec|execSync|execFile|execFileSync|fork|spawn|spawnSync|runInThisContext|runInNewContext|runInContext|compileFunction)$")
      arguments: (arguments
        (identifier) @sink_arg
      )
    ) @finding
  )
  (#eq? @tainted_var @sink_arg)
)

;; Pattern D: 1-hop taint from an assignment expression (`var x; x = atob(...); eval(x)`)
(
  (expression_statement
    (assignment_expression
      left: (identifier) @tainted_var
      right: (call_expression
        function: [
          (identifier) @decode_fn
          (member_expression property: (property_identifier) @decode_fn)
        ]
        (#match? @decode_fn "^(atob|unescape|fromCharCode|fromBase64|decompress|inflateSync|gunzipSync)$")
      )
    )
  )
  (_)*
  (expression_statement
    (call_expression
      function: [
        (identifier) @sink_fn
        (member_expression property: (property_identifier) @sink_fn)
      ]
      (#match? @sink_fn "^(eval|Function|exec|execSync|execFile|execFileSync|fork|spawn|spawnSync|runInThisContext|runInNewContext|runInContext|compileFunction)$")
      arguments: (arguments
        (identifier) @sink_arg
      )
    ) @finding
  )
  (#eq? @tainted_var @sink_arg)
)
