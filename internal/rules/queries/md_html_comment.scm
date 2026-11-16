;; Rule: MD-INJ-001 (HIGH)
;; Detects hidden AI prompt injection directives, tool-call overrides, or shell
;; execution instructions concealed inside Markdown HTML comment blocks (<!-- ... -->).
;; Plain words like "execute", "MCP", or "post" are not enough: commented-out
;; diagrams and PR templates use them constantly.

(html_block) @finding
(#match? @finding "(?i)<!--([\\s\\S]*?)(ignore (all |previous |prior )?(instructions|prompts)|system prompt|you are now|important:[^\\n]{0,80}\\b(you|agent|assistant|model|ai)\\b|do not (mention|tell|reveal)|\\b(you|agent|assistant) (must|should) (run|execute)\\b|curl [^\\n]*\\|\\s*(ba)?sh|wget [^\\n]*\\|\\s*(ba)?sh|bash -c|nc -e|<tool_call>|~/\\.ssh|id_rsa|\\.aws/credentials|exfiltrat)([\\s\\S]*?)-->")
