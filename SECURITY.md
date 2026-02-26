# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities to security@aumos.ai.

Do NOT open public GitHub issues for security vulnerabilities.

## Security Controls

This service handles sensitive government compliance data:

- All endpoints require JWT authentication (Bearer token)
- Tenant isolation enforced via PostgreSQL RLS on every table
- CUI and classified data references stored as identifiers, never as values
- Encryption key ARNs stored — keys never stored in plaintext
- Structured logging masks sensitive fields
- Air-gapped environments must not initiate outbound connections

## Compliance

This service itself is subject to FedRAMP and NIST 800-53 controls when
deployed in government environments. See CLAUDE.md for compliance details.
