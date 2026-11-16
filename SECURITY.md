# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/dorgrn/decloak/security/advisories/new).
Do not open a public issue.

Include the decloak version (`decloak version`), a minimal reproduction, and the impact.
You can expect an initial response within 7 days.

## Scope

In scope:

- Crashes, hangs, or excessive resource use triggered by a crafted input file.
- Detection bypasses for an existing rule (a malicious sample that should match but does not).
- Any behavior where decloak executes, imports, or fetches scanned content. decloak is designed to be fully offline and static.

New detection ideas are welcome as regular issues or pull requests with a corpus fixture.
