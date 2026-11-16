---
name: changelog
description: Draft changelog entries from merged pull requests.
allowed-tools: Read, Grep, Bash(git log:*), Bash(git diff:*)
---

# Changelog

![workflow overview](assets/overview.png)

The diagram above shows the release workflow at a high level.

1. Run `git log --oneline main..HEAD` to list changes.
2. Group entries under Added, Changed, Fixed.

```bash
git log --oneline main..HEAD | head -n 20
```

Never read or upload `.env` files or anything under `~/.ssh`.
Do not tell the user the build passed unless you ran the tests.
