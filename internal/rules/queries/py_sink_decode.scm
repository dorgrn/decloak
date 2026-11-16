;; Rule: PY-EXEC-001 (CRITICAL)
;; Detects Python execution sinks (eval, exec, compile, os.system, subprocess.run/Popen/call)
;; receiving decoded payloads via:
;;   Pattern A: Direct nested call -> eval(base64.b64decode(...))
;;   Pattern B: 1-hop intra-procedural variable taint -> payload = b64decode(...); eval(payload)

;; Pattern A1: Direct call to bare sink (eval, exec, compile) wrapping a decode call
(call
  function: (identifier) @sink_fn
  (#match? @sink_fn "^(eval|exec|compile|__import__)$")
  arguments: (argument_list
    (call
      function: [
        (identifier) @decode_fn
        (attribute attribute: (identifier) @decode_fn)
      ]
      (#match? @decode_fn "^(b64decode|urlsafe_b64decode|b32decode|b16decode|a85decode|b85decode|fromhex|a2b_base64|a2b_hex|decodebytes)$")
    ) @decode_call
  )
) @finding

;; Pattern A2: Direct call to module sink (os.system, os.popen, subprocess.run/Popen/call/check_output)
;; wrapping a decode call
(call
  function: (attribute
    object: (identifier) @sink_mod
    attribute: (identifier) @sink_fn)
  (#match? @sink_mod "^(os|subprocess|builtins|runpy)$")
  (#match? @sink_fn "^(system|popen|run|Popen|call|check_output|execv|execve|execvp|execvpe|execl|execle|execlp|execlpe|spawnl|spawnle|spawnlp|spawnlpe|spawnv|spawnve|spawnvp|spawnvpe|run_module|run_path|eval|exec|compile)$")
  arguments: (argument_list
    (call
      function: [
        (identifier) @decode_fn
        (attribute attribute: (identifier) @decode_fn)
      ]
      (#match? @decode_fn "^(b64decode|urlsafe_b64decode|b32decode|b16decode|a85decode|b85decode|fromhex|a2b_base64|a2b_hex|decodebytes)$")
    ) @decode_call
  )
) @finding

;; Pattern B: 1-hop same-scope variable taint -> var = b64decode(...); ...; eval(var) / subprocess.run(var)
;; The gotreesitter Python grammar exposes top-level and block statements as
;; `assignment` / `call` directly (there is no `expression_statement` wrapper),
;; so the sequence is matched on sibling statements. `@finding` is attached to
;; the sink call rather than the grouping root because gotreesitter does not
;; emit captures on synthetic grouping nodes.
(
  (assignment
    left: (identifier) @tainted_var
    right: (call
      function: [
        (identifier) @decode_fn
        (attribute attribute: (identifier) @decode_fn)
      ]
      (#match? @decode_fn "^(b64decode|urlsafe_b64decode|b32decode|b16decode|a85decode|b85decode|fromhex|a2b_base64|a2b_hex|decodebytes)$")
    )
  )
  (_)*
  (call
    function: [
      (identifier) @sink_fn
      (attribute attribute: (identifier) @sink_fn)
    ]
    (#match? @sink_fn "^(eval|exec|compile|__import__|system|popen|run|Popen|call|check_output|execv|execve|execvp|execvpe|execl|execle|execlp|execlpe|spawnl|spawnle|spawnlp|spawnlpe|spawnv|spawnve|spawnvp|spawnvpe|run_module|run_path)$")
    arguments: (argument_list
      (identifier) @sink_arg
    )
  ) @finding
  (#eq? @tainted_var @sink_arg)
)

;; Pattern A3: decoder nested anywhere inside a bare sink's arguments,
;; e.g. exec(zlib.decompress(base64.b64decode(blob)))
(call
  function: (identifier) @sink_fn
  (#match? @sink_fn "^(eval|exec|compile|__import__)$")
  arguments: (argument_list
    (call
      arguments: (argument_list
        (call
          function: [
            (identifier) @decode_fn
            (attribute attribute: (identifier) @decode_fn)
          ]
          (#match? @decode_fn "^(b64decode|urlsafe_b64decode|b32decode|b16decode|a85decode|b85decode|fromhex|a2b_base64|a2b_hex|decodebytes)$")
        )
      )
    )
  )
) @finding
