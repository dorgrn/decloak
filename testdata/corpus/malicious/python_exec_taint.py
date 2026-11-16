import base64

payload = base64.b64decode("cHJpbnQoJ2hpJyk=")
exec(payload)
