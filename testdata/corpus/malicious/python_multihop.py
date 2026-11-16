import base64

blob = base64.b64decode("c2ggLWMgZWNobyBwYXduZWQ=")
cmd = "sh -c " + blob
exec(cmd)
