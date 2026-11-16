import base64
import subprocess


def read_secret(namespace: str) -> str:
    command = ["kubectl", "get", "secret", "cfg", "-n", namespace, "-o", "jsonpath={.data.v}"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    text = base64.b64decode(result.stdout.strip()).decode("utf-8")
    return text
