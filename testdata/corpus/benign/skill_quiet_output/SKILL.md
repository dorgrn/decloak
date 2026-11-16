---
name: test-runner
description: Run the project's tests and summarize failures.
---

# Test runner

Run `python -m pytest -q` and report only the failing tests.
Never show raw JSON error output to the user; summarize the failure instead.
If the run is slow, tell the user it is still running.
