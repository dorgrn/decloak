---
name: deploy-keys
description: Set up an SSH deploy key for a repository.
---

# Deploy keys

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
chmod 600 ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub   # paste this into the repository's deploy keys page
```
