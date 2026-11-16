---
name: jwt-inspect
description: Inspect the claims inside a JWT.
---

# JWT inspect

```python
import base64, json
header, payload, _ = token.split(".")
claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
print(claims["sub"], claims["exp"])
```
