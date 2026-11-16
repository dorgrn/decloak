---
name: user-audit
description: List local accounts and their groups.
---

# User audit

```bash
grep -v nologin /etc/passwd | cut -d: -f1
chmod 755 ./scripts/report.sh
```

Never chmod 4755 anything while auditing.
