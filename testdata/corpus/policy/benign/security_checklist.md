# Security review

Audit the repository for common mistakes:

- Review which files the skill reads, especially `.env`, `.ssh`, and `.aws`.
- Confirm that no credential is uploaded to an external endpoint.
- Flag any `curl | bash` example that uses a raw IP address.
